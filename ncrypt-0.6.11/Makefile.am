# Makefile.am - build Makefile.in via automake
# $Id: Makefile.am,v 1.5 2004/03/17 04:51:30 s-nomad Exp $

AUTOMAKE_OPTIONS = foreign no-dependencies

bin_PROGRAMS = ncrypt

ncrypt_SOURCES = ncrypt.c decrypt_file.c encrypt_file.c \
	get_decryption_password.c get_encryption_password.c getopt.c getopt1.c \
	isaac.c mem.c rand_gen.c read_pass.c rijndael-alg-fst.c \
	rijndael-api-fst.c serpent.c sh1strhsh.c sha1.c twofish.c wipe_file.c

man_MANS = ncrypt.8

EXTRA_DIST = AUTHORS boxes-fst.dat ChangeLog COPYING INSTALL NEWS README TODO \
	config/install-sh config/missing config/mkinstalldirs \
	$(man_MANS)

DISTCLEANFILES = *~
