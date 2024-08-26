# A list of major upgrades and how to migrate

The following is a list of major changes to `bare`. To avoid making the top of this file increasingly irrelevant as time goes on, the upgrades are listed in reverse chronological order.

- - -

## 2024-08-26

### Synopsis
- makes bare.sh one big file
- creates `home` directory as opposed to `.var`, `.lib`, and `.etc`
- stops sourcing `~/.barerc`

### Migration tips

1. You'll no longer be able to run scripts from `.var/scripts` directory
2. The `~/.barerc` and `.etc/barerc` and `.lib/barerc` are no longer sourced
3. If you set up an alias for in your `~/.bashrc` (or similar), you'll need to tweak that to `bare.sh` (instead of `bare`)

You can run the following migration script to get those things back into context.

Copy and paste this into your terminal or make it an executable file. Run the script from the root of your `bare.sh` directory.

```bash
#!/usr/bin/env bash

{

	mkdir -p home
	for item in scripts recfiles downloads .cache; do
		mkdir -p "home/$item"
	done
	mkdir home/.cache/weather
	for item in document openai; do
		mkdir -p "home/recfiles/$item"
	done
	mkdir home/imports

	touch home/recfiles/document/list.rec
	touch home/recfiles/document/tags.rec
	for item in assistants messages threads; do
		touch home/recfiles/openai/$item.rec
	done

	cp -r .var home/imports/

	{
		mv home/imports/.var/.cache/weather/* home/.cache/weather/ && rm -rf home/imports/.var/.cache
		mv home/imports/.var/.cache/geo.txt home/.cache/ && rm -rf home/imports/.var/.cache/geo.txt
		mv home/imports/.var/sync home/version && rm -rf home/imports/.var/sync
		mv home/imports/.var/scripts/* home/scripts/ && rm -rf home/imports/.var/scripts
		mv home/imports/.var/documents home/desktop/ && rm -rf home/imports/.var/documents
		mv home/imports/.var/downloads home/downloads
		mv home/imports/.var/home/.??* home/imports/.var/home/* home/desktop/ && rm -rf home/imports/.var/home
		mv home/imports/.var/recfiles/* home/recfiles/ && rm -rf home/imports/.var/recfiles
		mkdir home/www && mv home/imports/.var/www home/www
		mkdir home/backups
		mv .etc home/backups/.etc && mv .var home/backups/.var
	} > /dev/null 2>&1

	db=home/imports/.var/bare.rec
	rec_dir=home/recfiles

	recsel $db -t Document >> $rec_dir/document/list.rec
	recsel $db -t Tag >> $rec_dir/document/tags.rec

	recsel $db -t Assistant >> $rec_dir/openai/assistants.rec
	recsel $db -t Thread >> $rec_dir/openai/threads.rec
	recsel $db -t ThreadMessage >> $rec_dir/openai/messages.rec

	rm $db

	# move everything else that might be there, including dotfiles
	mv home/imports/.var/.??* home/desktop/ && rm -rf home/imports

	{
		cat .etc/barerc >> home/.barerc
		echo "" >> home/.barerc
		cat ~/.barerc >> home/.barerc
		echo "" >> home/.barerc
	} > /dev/null 2>&1

	sleep 0.4
	echo ""
	echo "✅ Migration complete!"
	echo ""
	sleep 0.3
	echo ""
	echo "We copied and sorted everything accordingly and put"
	echo ".var and .etc in home/backups in case we missed anything."
	echo ""
	echo "Feel free to remove those if you're confident we got everything."
	echo ""
	echo "And consider removing any 'exports' in your home/.barerc file as exporting is no"
	echo "longer strictly necessecary here; normal variable assignment is okay."
	echo ""
	echo "Lastly, if you had 'bare' aliased in your shell rc file, you'll need to"
	echo "change that to '$(pwd)/bare.sh'. Don't forget to source your shell rc file."
	echo ""

}

```
