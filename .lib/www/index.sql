set page = '{
	"title" : "bare",
	"icon" : "code",
	"image" : "",
	"description" : "",
	"menu" : [
		{
			"title" : "Docs",
			"link" : "/docs/index.sql"
		},
		{
			"title" : "Contact",
			"link" : "/contact"
		}
	]
}'

select 'shell' as component,
	$site->>'title' as title,
	$site->>'menu' as menu_item,
	'dark' as theme,
	'/index.js' as javascript,
	'/assets/logo.webp' as image;

