set file = '.var/scripts/' || $title;
set response = sqlpage.exec('bare', 'write', :contents, $file);

select 'redirect' as component,
	'/scripts/show.sql?title=' || $title as link;