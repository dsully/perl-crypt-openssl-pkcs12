#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#define NOKEYS          0x1
#define NOCERTS         0x2
#define INFO            0x4
#define CLCERTS         0x8
#define CACERTS         0x10

const EVP_CIPHER *enc;

/* fake our package name */
typedef PKCS12*	Crypt__OpenSSL__PKCS12;

/* stolen from OpenSSL.xs */
long bio_write_cb(struct bio_st *bm, int m, const char *ptr, int l, long x, long y) {

        if (m == BIO_CB_WRITE) {
                SV *sv = (SV *) BIO_get_callback_arg(bm);
                sv_catpvn(sv, ptr, l);
        }

        if (m == BIO_CB_PUTS) {
                SV *sv = (SV *) BIO_get_callback_arg(bm);
                l = strlen(ptr);
                sv_catpvn(sv, ptr, l);
        }

        return l;
}

static BIO* sv_bio_create(void) {

        SV *sv = newSVpvn("",0);

	/* create an in-memory BIO abstraction and callbacks */
        BIO *bio = BIO_new(BIO_s_mem());

        BIO_set_callback(bio, bio_write_cb);
        BIO_set_callback_arg(bio, (void *)sv);

        return bio;
}

static SV* sv_bio_final(BIO *bio) {

	SV* sv;

	BIO_flush(bio);
	sv = (SV *)BIO_get_callback_arg(bio);
	BIO_free_all(bio);

	if (!sv) sv = &PL_sv_undef;

	return sv;
}

static void sv_bio_error(BIO *bio) {

	SV* sv = (SV *)BIO_get_callback_arg(bio);
	if (sv) sv_free(sv);

	BIO_free_all (bio);
}

static const char *ssl_error(void) {
	BIO *bio;
	SV *sv;
	STRLEN l;

	bio = sv_bio_create();
	ERR_print_errors(bio);
	sv = sv_bio_final(bio);
	ERR_clear_error();
	return SvPV(sv, l);
}

/* these are trimmed from their openssl/apps/pkcs12.c counterparts */
int dump_certs_pkeys_bag (BIO *bio, PKCS12_SAFEBAG *bag, char *pass, int passlen, int options, char *pempass) {

	X509 *x509;
	
	switch (M_PKCS12_bag_type(bag)) {

		case NID_certBag:

			if (options & NOCERTS) return 1;

			if (PKCS12_get_attr(bag, NID_localKeyID)) {

				if (options & CACERTS) return 1;

			} else if (options & CLCERTS) {

				return 1;
			}

			if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate) return 1;

			if (!(x509 = PKCS12_certbag2x509(bag))) return 0;

			PEM_write_bio_X509 (bio, x509);

			X509_free(x509);

			break;
	}

	return 1;
}

int dump_certs_pkeys_bags(BIO *bio, STACK_OF(PKCS12_SAFEBAG) *bags, char *pass, int passlen, int options, char *pempass) {

	int i;

	for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {

		if (!dump_certs_pkeys_bag (bio, sk_PKCS12_SAFEBAG_value (bags, i), pass, passlen, options, pempass)) {
			return 0;
		}
	}

	return 1;
}

int dump_certs_keys_p12(BIO *bio, PKCS12 *p12, char *pass, int passlen, int options, char *pempass) {

	STACK_OF(PKCS7) *asafes;
	STACK_OF(PKCS12_SAFEBAG) *bags;

	int i, bagnid;
	PKCS7 *p7;

	if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL) return 0;

	for (i = 0; i < sk_PKCS7_num(asafes); i++) {

		p7 = sk_PKCS7_value(asafes, i);

		bagnid = OBJ_obj2nid(p7->type);

		if (bagnid == NID_pkcs7_data) {

			bags = PKCS12_unpack_p7data(p7);
		
		} else if (bagnid == NID_pkcs7_encrypted) {

			bags = PKCS12_unpack_p7encdata(p7, pass, passlen);

		} else {
			continue;
		}

		if (!bags) return 0;

	    	if (!dump_certs_pkeys_bags(bio, bags, pass, passlen, options, pempass)) {

			sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
			return 0;
		}

		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	}

	sk_PKCS7_pop_free(asafes, PKCS7_free);

	return 1;
}

MODULE = Crypt::OpenSSL::PKCS12		PACKAGE = Crypt::OpenSSL::PKCS12		

PROTOTYPES: DISABLE

BOOT:
{
	OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();
        ERR_load_PKCS12_strings();
        ERR_load_ASN1_strings();
        ERR_load_crypto_strings();
        ERR_load_DSA_strings();
        ERR_load_RSA_strings();

	HV *stash = gv_stashpvn("Crypt::OpenSSL::PKCS12", 22, TRUE);

	struct { char *n; I32 v; } Crypt__OpenSSL__PKCS12__const[] = {
	{"NOKEYS", NOKEYS},
	{"NOCERTS", NOCERTS},
	{"INFO", INFO},
	{"CLCERTS", CLCERTS},
	{"CACERTS", CACERTS},
	{Nullch,0}};

	char *name;
	int i;

	for (i = 0; (name = Crypt__OpenSSL__PKCS12__const[i].n); i++) {
		newCONSTSUB(stash, name, newSViv(Crypt__OpenSSL__PKCS12__const[i].v));
	}
}

Crypt::OpenSSL::PKCS12
new(class)
	SV	*class

	CODE:

  	if ((RETVAL = PKCS12_new()) == NULL) {
		croak("Couldn't create PKCS12_new() for class %s", (char*)class);
	}

	OUTPUT:
        RETVAL

Crypt::OpenSSL::PKCS12
new_from_string(class, string)
	SV	*class
        SV	*string

	ALIAS:
   	new_from_file = 1     

	PREINIT:
	BIO *bio;
	STRLEN len;
	char *cert;

	CODE:

	cert = SvPV(string, len);

        if (ix == 1) {
		bio = BIO_new_file(cert, "r");
        } else {
		bio = BIO_new_mem_buf(cert, len);
	}

	if (!bio) croak("Failed to create BIO");

	/* this can come in any number of ways */
        if ((RETVAL = d2i_PKCS12_bio(bio, 0)) == NULL) {
		BIO_free(bio);
		croak("%s: Couldn't create PKCS12 from d2i_PKCS12_BIO(): %s", class, ssl_error());
	}

        BIO_free(bio);

	OUTPUT:
	RETVAL

void
DESTROY(pkcs12)
	Crypt::OpenSSL::PKCS12 pkcs12;

	CODE:
	if (pkcs12) PKCS12_free(pkcs12);

SV*
as_string(pkcs12)
	Crypt::OpenSSL::PKCS12 pkcs12;

	PREINIT:
	BIO *bio;

	CODE:

	bio = sv_bio_create();

	if (!(i2d_PKCS12_bio(bio, pkcs12))) {
		sv_bio_error(bio);
		croak("i2d_PKCS12_bio: %s", ssl_error());
	}

	RETVAL = sv_bio_final(bio);

	OUTPUT:
	RETVAL

SV*
mac_ok(pkcs12, pwd)
	Crypt::OpenSSL::PKCS12 pkcs12
	char *pwd

	CODE:
   	
	RETVAL = (PKCS12_verify_mac(pkcs12, pwd, strlen(pwd))) ? &PL_sv_yes : &PL_sv_no;

	OUTPUT:
	RETVAL

void
changepass(pkcs12, oldpwd, newpwd)
	Crypt::OpenSSL::PKCS12 pkcs12
	SV *oldpwd
	SV *newpwd

	PREINIT:
	char *op = 0;
	char *np = 0;

	CODE:

	STRLEN oldpwdlen;
	STRLEN newpwdlen;

	if (oldpwd != &PL_sv_undef) op = SvPV(oldpwd, oldpwdlen);
	if (newpwd != &PL_sv_undef) np = SvPV(newpwd, newpwdlen);

	if (!(PKCS12_newpass(pkcs12, op, np))) {
		croak("PKCS12_newpass: %s", ssl_error());
	}

SV*
certificate(pkcs12, pwd)
	Crypt::OpenSSL::PKCS12 pkcs12
	char *pwd

	PREINIT:
	BIO *bio;

	CODE:
   	
	bio = sv_bio_create();

	dump_certs_keys_p12(bio, pkcs12, pwd, strlen(pwd), CLCERTS|NOKEYS, NULL);

	RETVAL = sv_bio_final(bio);

	OUTPUT:
	RETVAL
