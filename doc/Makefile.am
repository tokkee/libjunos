EXTRA_DIST = junosc.txt
CLEANFILES = junosc.1

man_MANS = junosc.1

junosc.1: junosc.txt ../version

.txt.1:
	@A2X@ -d manpage -f manpage \
		-apackage_version=$(PACKAGE_VERSION) \
		-abuild_date="$$( date --utc '+%F' )" \
		$<

