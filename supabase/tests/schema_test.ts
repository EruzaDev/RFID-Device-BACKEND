import { PGlite } from 'npm:@electric-sql/pglite@0.5.9'

const db = new PGlite()
await db.exec('create role anon; create role authenticated;')
await db.exec(await Deno.readTextFile('./supabase/migrations/20261014000000_create_rfid_schema.sql'))
await db.exec(await Deno.readTextFile('./supabase/migrations/20261018000000_expand_process_stages.sql'))
await db.query("insert into public.devices(id,secret) values ('scanner-1', $1)", ['ab'.repeat(32)])
await db.exec("insert into public.students(uid,name) values ('A1B2C3D4','Alice')")
await db.exec("insert into public.items(uid,name) values ('01020304','Book')")
await db.exec("insert into public.loans(student_uid,item_uid,borrow_device) values ('A1B2C3D4','01020304','scanner-1')")
await db.exec("insert into public.device_state(device_id,mode,stage,updated_at) values ('scanner-1','borrow','scan_student',1)")
let preventedDuplicate = false
try {
  await db.exec("insert into public.loans(student_uid,item_uid,borrow_device) values ('A1B2C3D4','01020304','scanner-1')")
} catch {
  preventedDuplicate = true
}
if (!preventedDuplicate) throw new Error('Duplicate open loan was allowed')
await db.exec("update public.loans set returned_at = now(), return_device = 'scanner-1' where returned_at is null")
await db.exec("insert into public.loans(student_uid,item_uid,borrow_device) values ('A1B2C3D4','01020304','scanner-1')")
const rows = await db.query('select count(*)::int as count from public.loans')
if (rows.rows[0].count !== 2) throw new Error('Re-borrow after return failed')
for (const stage of ['checking_student', 'checking_item', 'wrong_tag', 'saving', 'retry_confirm', 'cancelled']) {
  await db.query('update public.device_state set stage = $1 where device_id = $2', [stage, 'scanner-1'])
}
await db.exec("update public.device_state set stage = 'error', error_code = 'already_borrowed'")
let privateErrorRejected = false
try {
  await db.exec("update public.device_state set error_code = 'UID A1B2C3D4'")
} catch { privateErrorRejected = true }
if (!privateErrorRejected) throw new Error('Free-form private error was accepted')
await db.exec("update public.device_state set stage = 'scan_student', error_code = null")
await db.exec('set role anon')
const publicState = await db.query('select stage from public.device_state')
if (publicState.rows[0].stage !== 'scan_student') throw new Error('Public state was not readable')
let protectedDeviceSecret = false
try {
  await db.query('select secret from public.devices')
} catch {
  protectedDeviceSecret = true
}
if (!protectedDeviceSecret) throw new Error('Anonymous role could read device secret')
await db.exec('reset role')
await db.close()
console.log('Schema and loan constraints passed')
