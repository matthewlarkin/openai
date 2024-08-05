set page = '{
	"title" : "bare",
	"icon" : "code",
	"image" : "",
	"description" : "",
	"menu" : [
		{
			"title" : "Terminal",
			"link" : "/terminal.sql"
		},
		{
			"title" : "Assistants",
			"link" : "/assistants/"
		},
		{
			"title" : "Scripts",
			"link" : "/scripts/"
		},
		{
			"title" : "Documents",
			"link" : "/documents/"
		}
	]
}';

select 'shell' as component,
	$page->>'title' as title,
	'/' as link,
	$page->>'menu' as menu_item,
	'/assets/js/highlight.js' as javascript,
	'/assets/css/highlight.css' as css,
	'/assets/js/simplemde.js' as javascript,
	'/assets/css/simplemde.css' as css,
	'/index.css' as css,
	'/index.js' as javascript,
	'/assets/logo.webp' as image;