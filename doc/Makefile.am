EXTRA_DIST = junosc.txt
CLEANFILES = junosc.1

man_MANS = junosc.1

junosc.1: junosc.1.txt ../version

%.1: %.1.txt
	@A2X@ -d manpage -f manpage \
		-apackage_version=$(PACKAGE_VERSION) \
		-abuild_date="$$( date --utc '+%F' )" \
		$<

