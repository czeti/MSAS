/* jes_checks.rex: Scan JES2 for security misconfigurations */
trace off
address TSO

findings.   = ''
findings.0  = 0


x = outtrap('jobs_output.')
'/$D JOBS' /* get list of jobs */
x = outtrap('off')

if jobs_output.0 = 0 then do
  call add_finding 'INFO', 'No jobs found in JES'
  signal emit_findings
end

held_jobs = 0
do i = 1 to jobs_output.0
  line = jobs_output.i
  
  if pos('HELD', line) > 0 | pos(' H ', line) > 0 then do
    held_jobs = held_jobs + 1
    parse var line jname jnum rest
    call add_finding 'WARNING', 'Held output detected for job' jname jnum
  end
end

call add_finding 'INFO', 'Total jobs in system:' jobs_output.0


x = outtrap('class_output.')
'/$D JOBCLASS' /* check job classes via /$D JOBCLASS*/
x = outtrap('off')

do i = 1 to class_output.0
  line = class_output.i
  if pos('CLASS=', line) > 0 then do
    parse var line . 'CLASS=' class .
    class = strip(class)
    /* if class is A (often privileged), warn */
    if class = 'A' then
      call add_finding 'WARNING', 'Privileged job class A exists'
    else if class = 'Z' then   /* example: could be other high-risk classes */
      call add_finding 'INFO', 'Job class' class 'is defined'
    else
      call add_finding 'INFO', 'Job class' class 'is defined'
  end
end


/* optional signal */
emit_findings:
say copies('-', 60)
say 'JES AUDIT FINDINGS:' findings.0 'item(s)'
say copies('-', 60)
if findings.0 = 0 then
  say 'INFO: No JES-related findings detected.'
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