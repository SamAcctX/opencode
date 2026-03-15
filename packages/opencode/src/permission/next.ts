import { runtime } from "@/effect/runtime"
import { Config } from "@/config/config"
import { fn } from "@/util/fn"
import { Wildcard } from "@/util/wildcard"
import { Effect } from "effect"
import { Yolo } from "@/yolo"
import os from "os"
import * as S from "./service"
import type {
  Action as ActionType,
  PermissionError,
  Reply as ReplyType,
  Request as RequestType,
  Rule as RuleType,
  Ruleset as RulesetType,
} from "./service"

export namespace PermissionNext {
  function expand(pattern: string): string {
    if (pattern.startsWith("~/")) return os.homedir() + pattern.slice(1)
    if (pattern === "~") return os.homedir()
    if (pattern.startsWith("$HOME/")) return os.homedir() + pattern.slice(5)
    if (pattern.startsWith("$HOME")) return os.homedir() + pattern.slice(5)
    return pattern
  }

  function runPromise<A>(f: (service: S.PermissionService.Api) => Effect.Effect<A, PermissionError>) {
    return runtime.runPromise(S.PermissionService.use(f))
  }

  export const Action = S.Action
  export type Action = ActionType
  export const Rule = S.Rule
  export type Rule = RuleType
  export const Ruleset = S.Ruleset
  export type Ruleset = RulesetType
  export const Request = S.Request
  export type Request = RequestType
  export const Reply = S.Reply
  export type Reply = ReplyType
  export const Approval = S.Approval
  export const Event = S.Event
  export const Service = S.PermissionService
  export const RejectedError = S.RejectedError
  export const CorrectedError = S.CorrectedError
  export const DeniedError = S.DeniedError

  export function fromConfig(permission: Config.Permission) {
    const ruleset: Ruleset = []
    for (const [key, value] of Object.entries(permission)) {
      if (typeof value === "string") {
        ruleset.push({
          permission: key,
          action: value,
          pattern: "*",
        })
        continue
      }
      ruleset.push(
        ...Object.entries(value).map(([pattern, action]) => ({ permission: key, pattern: expand(pattern), action })),
      )
    }
    return ruleset
  }

  export function merge(...rulesets: Ruleset[]): Ruleset {
    return rulesets.flat()
  }

  export const ask = fn(S.AskInput, async (input) => runPromise((service) => service.ask(input)))

  export const reply = fn(S.ReplyInput, async (input) => runPromise((service) => service.reply(input)))

  export async function list() {
    return runPromise((service) => service.list())
  }

  const state = Instance.state(() => {
    const projectID = Instance.project.id
    const row = Database.use((db) =>
      db.select().from(PermissionTable).where(eq(PermissionTable.project_id, projectID)).get(),
    )
    const stored = row?.data ?? ([] as Ruleset)

    return {
      pending: new Map<PermissionID, PendingEntry>(),
      approved: stored,
    }
  })

  export const ask = fn(
    Request.partial({ id: true }).extend({
      ruleset: Ruleset,
    }),
    async (input) => {
      const s = await state()
      const { ruleset, ...request } = input
      for (const pattern of request.patterns ?? []) {
        const rule = evaluate(request.permission, pattern, ruleset, s.approved)
        log.info("evaluated", { permission: request.permission, pattern, action: rule })
        if (rule.action === "deny")
          throw new DeniedError(ruleset.filter((r) => Wildcard.match(request.permission, r.permission)))
        if (rule.action === "ask") {
          // YOLO mode auto-approves all "ask" permissions (but respects explicit "deny")
          if (Yolo.isEnabled()) {
            log.warn("YOLO mode auto-approved", { permission: request.permission, pattern })
            continue
          }
          const id = input.id ?? PermissionID.ascending()
          return new Promise<void>((resolve, reject) => {
            const info: Request = {
              id,
              ...request,
            }
            s.pending.set(id, {
              info,
              resolve,
              reject,
            })
            Bus.publish(Event.Asked, info)
          })
        }
        if (rule.action === "allow") continue
      }
    },
  )

  export const reply = fn(
    z.object({
      requestID: PermissionID.zod,
      reply: Reply,
      message: z.string().optional(),
    }),
    async (input) => {
      const s = await state()
      const existing = s.pending.get(input.requestID)
      if (!existing) return
      s.pending.delete(input.requestID)
      Bus.publish(Event.Replied, {
        sessionID: existing.info.sessionID,
        requestID: existing.info.id,
        reply: input.reply,
      })
      if (input.reply === "reject") {
        existing.reject(input.message ? new CorrectedError(input.message) : new RejectedError())
        // Reject all other pending permissions for this session
        const sessionID = existing.info.sessionID
        for (const [id, pending] of s.pending) {
          if (pending.info.sessionID === sessionID) {
            s.pending.delete(id)
            Bus.publish(Event.Replied, {
              sessionID: pending.info.sessionID,
              requestID: pending.info.id,
              reply: "reject",
            })
            pending.reject(new RejectedError())
          }
        }
        return
      }
      if (input.reply === "once") {
        existing.resolve()
        return
      }
      if (input.reply === "always") {
        for (const pattern of existing.info.always) {
          s.approved.push({
            permission: existing.info.permission,
            pattern,
            action: "allow",
          })
        }

        existing.resolve()

        const sessionID = existing.info.sessionID
        for (const [id, pending] of s.pending) {
          if (pending.info.sessionID !== sessionID) continue
          const ok = pending.info.patterns.every(
            (pattern) => evaluate(pending.info.permission, pattern, s.approved).action === "allow",
          )
          if (!ok) continue
          s.pending.delete(id)
          Bus.publish(Event.Replied, {
            sessionID: pending.info.sessionID,
            requestID: pending.info.id,
            reply: "always",
          })
          pending.resolve()
        }

        // TODO: we don't save the permission ruleset to disk yet until there's
        // UI to manage it
        // db().insert(PermissionTable).values({ projectID: Instance.project.id, data: s.approved })
        //   .onConflictDoUpdate({ target: PermissionTable.projectID, set: { data: s.approved } }).run()
        return
      }
    },
  )

  export function evaluate(permission: string, pattern: string, ...rulesets: Ruleset[]): Rule {
    return S.evaluate(permission, pattern, ...rulesets)
  }

  const EDIT_TOOLS = ["edit", "write", "patch", "multiedit"]

  export function disabled(tools: string[], ruleset: Ruleset): Set<string> {
    const result = new Set<string>()
    for (const tool of tools) {
      const permission = EDIT_TOOLS.includes(tool) ? "edit" : tool
      const rule = ruleset.findLast((rule) => Wildcard.match(permission, rule.permission))
      if (!rule) continue
      if (rule.pattern === "*" && rule.action === "deny") result.add(tool)
    }
    return result
  }
}
