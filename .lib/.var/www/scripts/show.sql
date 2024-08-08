select 'dynamic' as component, sqlpage.run_sql('shell.sql') as properties;

select 'title' as component,
	'Scripts / ' || $title as contents;

select 'code-editor' as component,
	'/scripts/update.sql?title=' || $title as action,
	'contents' as name,
	sqlpage.read_file_as_text('../../.var/scripts/' || $title) as value,
	'Save' as validate;