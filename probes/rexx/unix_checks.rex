/* Scan OMVS (USS) for security issues */
trace off
address TSO

findings.   = ''
findings.0  = 0

   /* check world writable directories under / */
call run_uss_cmd 'find / -type d -perm -0002 -print 2>/dev/null | head -20'
if stem.0 > 0 then do i = 1 to stem.0
  dir = strip(stem.i)
  if dir \= '' then
    call add_finding 'WARNING', 'World-writable directory' dir
end

   /* check SUID files under / (setuid root) */
call run_uss_cmd 'find / -type f -perm -4000 -ls 2>/dev/null | head -20'
if stem.0 > 0 then do i = 1 to stem.0
  line = strip(stem.i)
  if line \= '' then
    call add_finding 'INFO', 'SUID file:' line
end

   /* check /tmp permissions */
call run_uss_cmd 'ls -ld /tmp'
if stem.0 > 0 then do i = 1 to stem.0
  line = strip(stem.i)
  if pos('drwxrwxrwt', line) = 0 then
    call add_finding 'WARNING', '/tmp has non-standard permissions:' line
end


emit_findings:
say copies('-', 60)
say 'UNIX AUDIT FINDINGS:' findings.0 'item(s)'
say copies('-', 60)
if findings.0 = 0 then
  say 'INFO: No Unix-related findings detected.'
else do i = 1 to findings.0
  say findings.i
end
say copies('-', 60)

exit 0


add_finding: procedure expose findings.
  parse arg severity, text
  n = findings.0 + 1
  findings.n = severity || ': ' || text
  findings.0 = n
return


run_uss_cmd: procedure expose stem. findings.
  parse arg cmd
  stem.  = ''
  stem.0 = 0
  x = outtrap('stem.')
  address sh cmd
  x = outtrap('off')
return