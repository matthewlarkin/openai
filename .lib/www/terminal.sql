select 'dynamic' as component, sqlpage.run_sql('shell.sql') as properties;

select 'title' as component,
	'Terminal' as contents;

set touch_terminal_results = sqlpage.exec('touch', '../../.var/scripts/.terminal-script');

select 'code-editor' as component,
	'/execute.sql' as action,
	'script' as name,
	sqlpage.read_file_as_text('../../.var/scripts/.terminal-script') as value,
	'Execute' as validate;

set remove_terminal_script = sqlpage.exec('rm', '../../.var/scripts/.terminal-script');
set touch_terminal_results = sqlpage.exec('touch', '../../.var/.cache/terminal-results.md');
set terminal_results = sqlpage.read_file_as_text('../../.var/.cache/terminal-results.md');

select 'divider' as component;

select 'title' as component,
	'Results' as contents
	where $terminal_results != '';

select 'text' as component,
	'col-md-6 my-4' as class,
	$terminal_results as contents_md;

set clear_cache = sqlpage.exec('rm', '../../.var/.cache/terminal-results.md');