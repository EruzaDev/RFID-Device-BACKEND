import postgres from 'npm:postgres@3.4.5'

const databaseUrl = Deno.env.get('SUPABASE_DB_URL')
if (!databaseUrl) throw new Error('SUPABASE_DB_URL is required')
// Supabase's transaction pooler does not support prepared statements.
const sql = postgres(databaseUrl, { prepare: false, max: 1 })

const uidPattern = /^([0-9A-F]{8}|[0-9A-F]{14}|[0-9A-F]{20})$/
const tokenPattern = /^[A-Za-z0-9_-]{1,64}$/
const hex32 = /^[0-9a-f]{32}$/
const hex64 = /^[0-9a-f]{64}$/
const stages = new Set(['idle', 'scan_student', 'scan_item', 'confirm', 'success', 'error'])
const messages: Record<string, string> = {
  idle: 'Standby Monitor',
  scan_student: 'Tap Student ID',
  scan_item: 'Tap Equipment Tag',
  confirm: 'Await Confirmation',
  success: 'Transaction Complete',
  error: 'Transaction Not Accepted',
}
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type, x-device-id, x-timestamp, x-nonce, x-signature',
  'Cache-Control': 'no-store',
}
const encoder = new TextEncoder()

class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message)
  }
}

function json(status: number, payload: unknown): Response {
  return Response.json(payload, { status, headers: corsHeaders })
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

function unhex(value: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(value.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let difference = 0
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i]
  return difference === 0
}

async function authenticate(request: Request, route: string, raw: Uint8Array<ArrayBuffer>): Promise<string> {
  const deviceId = request.headers.get('x-device-id') ?? ''
  const timestamp = request.headers.get('x-timestamp') ?? ''
  const nonce = request.headers.get('x-nonce') ?? ''
  const signature = request.headers.get('x-signature') ?? ''
  if (!tokenPattern.test(deviceId) || !/^\d+$/.test(timestamp) || !hex32.test(nonce) || !hex64.test(signature)) {
    throw new ApiError(401, 'auth_failed', 'Invalid device credentials')
  }
  const seconds = Number(timestamp)
  if (!Number.isSafeInteger(seconds) || Math.abs(Math.floor(Date.now() / 1000) - seconds) > 300) {
    throw new ApiError(401, 'clock_skew', 'Device clock differs by more than 5 minutes')
  }
  const devices = await sql`select secret from public.devices where id = ${deviceId} and active = true`
  if (devices.length !== 1) throw new ApiError(401, 'auth_failed', 'Invalid device credentials')
  const signed = `POST\n${route}\n${timestamp}\n${nonce}\n${await sha256(raw)}`
  const key = await crypto.subtle.importKey('raw', unhex(devices[0].secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const expected = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(signed)))
  if (!sameBytes(expected, unhex(signature))) {
    throw new ApiError(401, 'auth_failed', 'Invalid device credentials')
  }
  const inserted = await sql`
    insert into public.nonces(device_id, nonce) values (${deviceId}, ${nonce})
    on conflict do nothing returning nonce
  `
  if (inserted.length !== 1) throw new ApiError(401, 'replay', 'Request was already received')
  await sql`delete from public.nonces where seen_at < now() - interval '10 minutes'`
  return deviceId
}

function objectWithKeys(value: unknown, keys: string[]): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}

function validUid(value: unknown): value is string {
  return typeof value === 'string' && uidPattern.test(value)
}

type ScanBody = { mode: 'borrow' | 'return'; student_uid: string; item_uid: string | null }

function scanBody(value: unknown, committing: boolean): ScanBody & { request_id?: string } {
  const keys = committing ? ['mode', 'student_uid', 'item_uid', 'request_id'] : ['mode', 'student_uid', 'item_uid']
  if (!objectWithKeys(value, keys)) throw new ApiError(400, 'bad_body', 'Unexpected or missing JSON fields')
  if (value.mode !== 'borrow' && value.mode !== 'return') {
    throw new ApiError(400, 'bad_mode', 'Mode must be borrow or return')
  }
  if (!validUid(value.student_uid) || (value.item_uid !== null && !validUid(value.item_uid))) {
    throw new ApiError(400, 'bad_uid', 'UID must be 4, 7, or 10 bytes of uppercase hex')
  }
  if (committing && (value.item_uid === null || typeof value.request_id !== 'string' || !hex32.test(value.request_id))) {
    throw new ApiError(400, 'bad_body', 'Item UID and 32-character request ID are required')
  }
  return value as ScanBody & { request_id?: string }
}

async function preview(body: ScanBody): Promise<Record<string, unknown>> {
  const students = await sql`select name from public.students where uid = ${body.student_uid} and active = true`
  if (students.length !== 1) throw new ApiError(404, 'student_unknown', 'Student ID not registered or inactive')
  if (body.item_uid === null) return { ok: true, student_name: students[0].name, next: 'scan_item' }
  const items = await sql`select name from public.items where uid = ${body.item_uid} and active = true`
  if (items.length !== 1) throw new ApiError(404, 'item_unknown', 'Item tag not registered or inactive')
  const loans = await sql`select student_uid from public.loans where item_uid = ${body.item_uid} and returned_at is null`
  if (body.mode === 'borrow' && loans.length) throw new ApiError(409, 'already_borrowed', 'Item is already borrowed')
  if (body.mode === 'return' && (!loans.length || loans[0].student_uid !== body.student_uid)) {
    throw new ApiError(409, 'wrong_borrower', 'No active loan for this student and item')
  }
  return { ok: true, student_name: students[0].name, item_name: items[0].name, next: 'confirm' }
}

async function commit(deviceId: string, body: ScanBody & { request_id?: string }): Promise<Record<string, unknown>> {
  const itemUid = body.item_uid!
  const requestId = body.request_id!
  const bodyHash = await sha256(encoder.encode(JSON.stringify({
    mode: body.mode, student_uid: body.student_uid, item_uid: itemUid, request_id: requestId,
  })))
  return await sql.begin(async tx => {
    // Serialize retries for the same request before checking the saved result.
    await tx`select pg_advisory_xact_lock(hashtext(${deviceId}), hashtext(${requestId}))`
    const previous = await tx`
      select body_hash, response from public.requests where device_id = ${deviceId} and request_id = ${requestId}
    `
    if (previous.length) {
      if (previous[0].body_hash !== bodyHash) {
        throw new ApiError(409, 'request_reused', 'Request ID was used with different data')
      }
      return previous[0].response as Record<string, unknown>
    }

    const students = await tx`select name from public.students where uid = ${body.student_uid} and active = true`
    if (students.length !== 1) throw new ApiError(404, 'student_unknown', 'Student ID not registered or inactive')
    // Locking the item row serializes competing borrow/return attempts.
    const items = await tx`select name from public.items where uid = ${itemUid} and active = true for update`
    if (items.length !== 1) throw new ApiError(404, 'item_unknown', 'Item tag not registered or inactive')
    const loans = await tx`
      select id, student_uid from public.loans where item_uid = ${itemUid} and returned_at is null
    `
    if (body.mode === 'borrow') {
      if (loans.length) throw new ApiError(409, 'already_borrowed', 'Item is already borrowed')
      await tx`
        insert into public.loans(student_uid, item_uid, borrow_device)
        values (${body.student_uid}, ${itemUid}, ${deviceId})
      `
    } else {
      if (!loans.length || loans[0].student_uid !== body.student_uid) {
        throw new ApiError(409, 'wrong_borrower', 'No active loan for this student and item')
      }
      await tx`update public.loans set returned_at = now(), return_device = ${deviceId} where id = ${loans[0].id}`
    }
    const result = {
      ok: true, mode: body.mode, student_name: students[0].name,
      item_name: items[0].name, recorded_at: Math.floor(Date.now() / 1000),
    }
    await tx`
      insert into public.requests(device_id, request_id, body_hash, response)
      values (${deviceId}, ${requestId}, ${bodyHash}, ${JSON.stringify(result)}::jsonb)
    `
    return result
  })
}

async function getState(deviceId: string | null): Promise<Record<string, unknown>> {
  if (!deviceId || !tokenPattern.test(deviceId)) throw new ApiError(400, 'bad_device', 'Invalid device ID')
  const devices = await sql`select id from public.devices where id = ${deviceId} and active = true`
  if (devices.length !== 1) throw new ApiError(404, 'device_unknown', 'Device not found')
  const states = await sql`select mode, stage, updated_at from public.device_state where device_id = ${deviceId}`
  const state = states[0] ?? { mode: 'borrow', stage: 'idle', updated_at: 0 }
  return {
    device_id: deviceId, mode: state.mode, stage: state.stage,
    message: messages[state.stage], updated_at: Number(state.updated_at),
  }
}

async function saveState(deviceId: string, body: unknown): Promise<{ ok: true }> {
  if (!objectWithKeys(body, ['mode', 'stage'])) throw new ApiError(400, 'bad_body', 'Mode and stage are required')
  if ((body.mode !== 'borrow' && body.mode !== 'return') || typeof body.stage !== 'string' || !stages.has(body.stage)) {
    throw new ApiError(400, 'bad_state', 'Invalid device mode or stage')
  }
  await sql`
    insert into public.device_state(device_id, mode, stage, updated_at)
    values (${deviceId}, ${body.mode}, ${body.stage}, ${Date.now()})
    on conflict (device_id) do update set
      mode = excluded.mode, stage = excluded.stage, updated_at = excluded.updated_at
  `
  return { ok: true }
}

function publicConfig(origin: string): Record<string, string> {
  const configured = Deno.env.get('SUPABASE_PUBLISHABLE_KEYS')
  let key: unknown
  if (configured) {
    const keys = JSON.parse(configured) as Record<string, unknown>
    key = keys.default ?? Object.values(keys)[0]
  }
  key ??= Deno.env.get('SUPABASE_ANON_KEY')
  if (typeof key !== 'string' || !key) throw new Error('No Supabase publishable key configured')
  return { supabase_url: origin, publishable_key: key }
}

async function handle(request: Request): Promise<Response> {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders })
  const url = new URL(request.url)
  const match = /\/rfid-api(\/api\/v1\/(?:health|config|state|preview|commit))$/.exec(url.pathname)
  const route = match?.[1]
  if (!route) return json(404, { ok: false, code: 'not_found', message: 'Unknown route' })
  try {
    if (request.method === 'GET') {
      if (route === '/api/v1/health' && !url.search) return json(200, { ok: true })
      if (route === '/api/v1/config' && !url.search) return json(200, publicConfig(url.origin))
      if (route === '/api/v1/state' && url.searchParams.size === 1) {
        return json(200, await getState(url.searchParams.get('device_id')))
      }
      throw new ApiError(404, 'not_found', 'Unknown route')
    }
    if (request.method !== 'POST' || route === '/api/v1/health' || route === '/api/v1/config') {
      throw new ApiError(405, 'method_not_allowed', 'Method not allowed')
    }
    const raw = new Uint8Array(await request.arrayBuffer())
    if (raw.length < 1 || raw.length > 1024) throw new ApiError(400, 'bad_body', 'JSON body must be 1 to 1024 bytes')
    const deviceId = await authenticate(request, route, raw)
    let body: unknown
    try {
      body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw))
    } catch {
      throw new ApiError(400, 'bad_json', 'Invalid JSON')
    }
    if (route === '/api/v1/state') return json(200, await saveState(deviceId, body))
    if (route === '/api/v1/preview') return json(200, await preview(scanBody(body, false)))
    return json(200, await commit(deviceId, scanBody(body, true)))
  } catch (error) {
    if (error instanceof ApiError) return json(error.status, { ok: false, code: error.code, message: error.message })
    console.error(error)
    return json(500, { ok: false, code: 'server_error', message: 'Server error' })
  }
}

export default { fetch: handle }
