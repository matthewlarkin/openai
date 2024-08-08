set expression = "Title = '" || $title || "'";
set contents_update = sqlpage.exec('bare', 'rec', 'update', '.var/bare.rec', '-t', 'Document', '-e', $expression, '-f', 'Contents', '-s', :contents);
set title_update = sqlpage.exec('bare', 'rec', 'update', '.var/bare.rec', '-t', 'Document', '-e', $expression, '-f', 'Title', '-s', :title);

select 'redirect' as component,
	'/documents/show.sql?title=' || :title as link;