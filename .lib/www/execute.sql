set terminal_script = sqlpage.exec('bare', 'write', :script, '.var/scripts/.terminal-script')

set response = sqlpage.exec('bare', 'run', '.terminal-script');

set tmp_result = sqlpage.exec('bare', 'write', $response, '.var/.cache/terminal-results.md');

select 'redirect' as component,
	'/terminal.sql' as link;