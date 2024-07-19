select 'shell' as component,
	$page->>'title' as title,
	'dark' as theme,
	'/index.js' as javascript,
	$site->>'menu' as menu_item;