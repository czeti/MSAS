/* Check for weak dataset permissions */
trace off
address TSO

findings.   = ''
findings.0  = 0

x = outtrap('profile_list.')
'SEARCH CLASS(DATASET) FILTER(SYS1.**)'
x = outtrap('off')

if profile_list.0 = 0 then do
  call add_finding 'INFO', 'No SYS1 dataset profiles found via SEARCH'
  signal emit_findings
end

do i = 1 to profile_list.0
  profile = strip(profile_list.i)
  if profile = '' then iterate

  /* always record that we examined this profile */
  call add_finding 'INFO', 'Scanned dataset profile' profile

  x = outtrap('dsd_output.')
  'LISTDSD DATASET('''profile''')'
  x = outtrap('off')

  uacc    = ''
  id_star = 0

  do j = 1 to dsd_output.0
    line = dsd_output.j
    if pos('UACC=', line) > 0 then do
      parse var line . 'UACC=' uacc .
      uacc = strip(uacc)
    end
    if pos('ID=', line) > 0 then do
      parse var line . 'ID=' id .
      if strip(id) = '*' then id_star = 1
    end
  end

  if uacc = 'READ' | uacc = 'UPDATE' | uacc = 'ALTER' then
    call add_finding 'WARNING', 'Dataset' profile 'has UACC('uacc')'
  if id_star then
    call add_finding 'WARNING', 'Dataset' profile 'grants access to ID(*)'
end

emit_findings:
say copies('-', 60)
say 'DATASET AUDIT FINDINGS:' findings.0 'item(s)'
say copies('-', 60)
if findings.0 = 0 then
  say 'INFO: No weak dataset permissions detected.'
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