select 'shell' as component,
	$page->>'title' as title,
	'dark' as theme,
	'/index.js' as javascript,
	$site->>'menu' as menu_item;

set scripts = sqlpage.exec('bare', 'rec', 'select', '.var/bare.rec', '-t', 'Script', '--as', 'json');

select 'list' as component;

	select json_extract(value, '$.Title') as title,
		'/scripts/show.sql?title=' || sqlpage.url_encode(json_extract(value, '$.Title')) as link
		from json_each($scripts);
