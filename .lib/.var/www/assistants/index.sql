select 'dynamic' as component, sqlpage.run_sql('shell.sql') as properties;

select 'title' as component,
	'Assistants' as contents;

set assistants = sqlpage.exec('recsel', '../../.var/bare.rec', '-t', 'Assistant', '-P', 'Name', '-C');
set array = sqlpage.exec('jq', '-n', '--arg', 'output', $assistants, '$output | split("\n") | map(select(length > 0) | {name: .})');

select 'list' as component;

	select json_extract(value, '$.name') as title,
		'/assistants/show.sql?name=' || json_extract(value,'$.name') as link
		from json_each($array);