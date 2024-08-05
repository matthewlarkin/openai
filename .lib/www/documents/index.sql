select 'dynamic' as component, sqlpage.run_sql('shell.sql') as properties;

select 'title' as component,
	'Documents' as contents;

set documents = sqlpage.exec('recsel', '../../.var/bare.rec', '-t', 'Document', '-P', 'Title', '-C');
set array = sqlpage.exec('jq', '-n', '--arg', 'output', $documents, '$output | split("\n") | map(select(length > 0) | {title: .})');

select 'list' as component;

	select json_extract(value, '$.title') as title,
		'/documents/show.sql?title=' || json_extract(value,'$.title') as link
		from json_each($array);