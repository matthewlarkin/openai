select 'dynamic' as component, sqlpage.run_sql('shell.sql') as properties;

select 'title' as component,
	'Documents / ' || $title as contents;

set expression = "Title = '" || $title || "'";

select 'form' as component,
	'/documents/update.sql?title=' || $title as action,
	'col-md-10' as class,
	'markdown_form' as id,
	'Save' as validate;

select 'text' as type,
	'Title' as label,
	'title' as name,
	$title as value;

select 'textarea' as type,
	'Contents' as label,
	'simplemde' as id,
	6 as rows,
	'contents' as name,
	sqlpage.exec('recsel', '../../.var/bare.rec', '-t', 'Document', '-P', 'Contents', '-e', $expression) as value;