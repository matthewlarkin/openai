select 'shell' as component,
	'fluid' as layout,
	' ' as footer;

set expression = "Title = '" || $title || "'";
set contents = sqlpage.exec('bare', 'rec', 'select', '.var/bare.rec', '-t', 'Document', '-P', 'Contents', '-e', $expression);

select 'title' as component,
	$title as contents;

select 'text' as component,
	$contents as contents_md;