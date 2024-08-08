select 'dynamic' as component, sqlpage.run_sql('shell.sql') as properties;

select 'title' as component,
	'Assistants / ' || $name as contents;

set expression = "Name = '" || $name ||  "'";

select 'form' as component,
	'/assistants/update.sql?name=' || $name as action,
	'col-md-6' as class,
	'Save' as validate;

select 'textarea' as type,
	'Contents' as label,
	6 as rows,
	'contents' as name,
	sqlpage.exec('bare', 'rec', 'select', '.var/bare.rec', '-t', 'Assistant', '-P', 'Contents', '-e', $expression) as value;