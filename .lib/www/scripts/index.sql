select 'dynamic' as component, sqlpage.run_sql('shell.sql') as properties;

select 'title' as component,
	'Scripts' as contents;

set scripts = sqlpage.exec('ls', '../../.var/scripts');
set array = sqlpage.exec('jq', '-n', '--arg', 'output', $scripts, '$output | split("\n") | map(select(length > 0) | {file: .})');

select 'list' as component;

	select json_extract(value, '$.file') as title,
		'/scripts/show.sql?title=' || json_extract(value,'$.file') as link
		from json_each($array);

-- select 'text' as component,
-- 	'hello' as contents;