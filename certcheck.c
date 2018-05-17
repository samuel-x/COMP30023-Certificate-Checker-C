/*  Computer Systems COMP30023 Part A
*   name: Samuel Xu 
*   studentno: #835273
*   email: samuelx@student.unimelb.edu.au
*   login: samuelx
*
*   Using the provided skeleton code given in the gitlab repo "Assignment2"
*
*   This is a simple program which verifies certificates in the following
*	categories:
*		- The certificate must have valid validity dates
*
*		- The certificate must have a valid domain name (as well as SANs)
*
*		- The certificate must have a minimum key length of 2048 bits for RSA
*
*		- The certificate must use the key correctly, including extensions 
*
*   Style Notes:
*   Following the provided  style, we'll be doing the following:
*       - Character ruler of 78 characters. This allows us to read in consoles
*           like VI or nano without word wrap
*
*       - Use underscores when there are names_with_spaces, in both functions
*           and variables
*
*       - We'll be putting asterisks before the variable names, not the type
*           (allows us to define pointers and normal types in the same line)
*
*       - #defines are ALL_CAPITAL_LETTERS
*
*       - Convert tabs to spaces
*
*/

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define RED     "\x1b[31m"
#define GRE   	"\x1b[32m"
#define YEL  	"\x1b[33m"
#define BLU    	"\x1b[34m"
#define MAG 	"\x1b[35m"
#define CYA   	"\x1b[36m"
#define RES   	"\x1b[0m"

#define WILDCARD "*"
#define TEST_DIR "./sample_certs/"

#define TRUE 1
#define FALSE 0

static void *safe_malloc(size_t size) {
    // This malloc checks if a malloc has completed successfully before
    // continuing
    void *pointer = malloc(size);
    if (!pointer) {
        perror("Bad malloc, out of memory!\n");
        exit(1);
    }

    return pointer;
}

int check_time(X509_CINF *info);
int contains_wildcard(char* domain);
int wildcard_match(char* wildcard_domain, char* domain);
int check_subject(X509 *cert, char* domain);
int check_domain(X509 *cert, char* domain);

int main(int argc, const char *argv[])
{
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL;

    X509_CINF *cert_inf = NULL;
    int valid = TRUE;
    STACK_OF(X509_EXTENSION) * ext_list;

    // To read in our CSV
    FILE *in = fopen(argv[1], "r");
    FILE *out = fopen("sample_output.csv", "w");
    char domain[256];
    char certificate_path[256];
    char *path;
    char *output;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    while (fscanf(in, "%30[^ ,\n\t],%s\n", certificate_path, domain) > 0) {
	    //Read certificate into BIO
	    path = (char *)safe_malloc(sizeof(char) 
	    	* (strlen(certificate_path) + strlen(TEST_DIR)));
	    sprintf(path, "%s%s", TEST_DIR, certificate_path);

	    printf(GRE "Read in: %s vs %s\n" RES, path, domain);
	    if (!(BIO_read_filename(certificate_bio, path)))
	    {
	        fprintf(stderr, "Error in reading cert BIO filename\n");
	        exit(EXIT_FAILURE);
	    }
	    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
	    {
	        fprintf(stderr, "Error in loading certificate\n");
	        exit(EXIT_FAILURE);
	    }

	    //cert contains the x509 certificate and can be used to analyse the certificate
	    
	    //*********************
	    // Example code of accessing certificate values
	    //*********************

    	valid = TRUE;
	    cert_inf = cert->cert_info;

	    // Validate the date of our certificate
	    if(!check_time(cert_inf)) {
	    	valid = FALSE;
	    }

		if(!check_subject(cert, domain)) {
			valid = FALSE;
		};

	    // Now check our domain name (as well as SAN)
	    if(!check_domain(cert, domain)) {
	    	valid = FALSE;
	    }



		output = (char *)safe_malloc(sizeof(char) 
	    	* (strlen(certificate_path)+strlen(domain)+4));

		sprintf(output, "%s,%s,%d\n", certificate_path, domain, valid);
	    fprintf(out, output);

	    memset(domain, 0, 256);
	    memset(certificate_path, 0, 256);
	}

    //*********************
    // End of Example code
    //*********************

	BIO_free_all(certificate_bio);
	X509_free(cert);
    fclose(in);
    fclose(out);
    exit(0);
}

int check_time(X509_CINF *info) {

	printf("Checking date...\n");
	// Define our variables
	const ASN1_TIME *valid_from;
	const ASN1_TIME *valid_to;
	int diff_day, diff_sec;

	// Get our validity dates
	valid_from = info->validity->notBefore;
	valid_to = info->validity->notAfter;

 	// Delete this after
	ASN1_TIME *current_time;
	time_t t;
	t = time(NULL);
	current_time = ASN1_TIME_adj(NULL, t, 0, 0);
	BIO *b;
	b = BIO_new_fp(stdout, BIO_NOCLOSE);
	printf(CYA "Valid From: " RES);
	ASN1_TIME_print(b, valid_from);
	printf(CYA "\nCurrently: " RES);
	ASN1_TIME_print(b, current_time);
	printf(CYA "\nValid To: " RES);
	ASN1_TIME_print(b, valid_to);
	printf("\n");
	BIO_free(b);

	// Check if we are past the issue date
 	if (!ASN1_TIME_diff(&diff_day, &diff_sec, valid_from, NULL)) {
        fprintf(stderr, "Error comparing validity dates in certificate.\n");
        exit(EXIT_FAILURE);
 	}
 	if (diff_day < 0 || diff_sec < 0) {
 		printf(RED "This certificate's notbefore date is not valid\n" RES);
 		return FALSE;
 	}

 	// Check if we are before the due date
 	if (!ASN1_TIME_diff(&diff_day, &diff_sec, NULL, valid_to)) {
        fprintf(stderr, "Error comparing validity dates in certificate.\n");
        exit(EXIT_FAILURE);
 	}
 	if (diff_day < 0 || diff_sec < 0) {
 		printf(RED "This certificate's notafter date is not valid\n" RES);
 		return FALSE;
 	}

	printf(GRE "This certificate's date is valid!\n\n" RES);
	return TRUE;
}

int check_subject(X509 *cert, char* domain) {
	X509_NAME *subject_issuer = NULL;
    subject_issuer = X509_get_subject_name(cert);

    ASN1_STRING *subject_domain;
    char *subject_domain_str = safe_malloc(sizeof(char) * strlen(domain));
    char *stripped_domain = safe_malloc(sizeof(char) * strlen(domain));
	X509_NAME_ENTRY *e;

	printf("Checking subject domain...\n");
	e = X509_NAME_get_entry(subject_issuer, 5);
	subject_domain = X509_NAME_ENTRY_get_data(e);
	ASN1_STRING_print_ex_fp(stdout, subject_domain, 1);
	printf("\n");

	subject_domain_str = ASN1_STRING_data(subject_domain);
	if (contains_wildcard(subject_domain_str)) {
		return wildcard_match(subject_domain_str, domain);
	}
	else {
		if (strcmp(subject_domain_str, domain) != 0) {
			printf(RED "%s and %s are not the same!\n" RES, subject_domain_str, domain);
		}
		else{
			printf(GRE "%s and %s are the same!\n" RES, subject_domain_str, domain);
		}
	}	
}

int contains_wildcard(char* domain) {
	// This function checks if the domain has a wildcard inside
	for (int i = 0; i < strlen(domain); i++) {
		if (domain[i] == WILDCARD) {
			return TRUE;
		}
	}
	return FALSE;
}

int wildcard_match(char* wildcard_domain, char* domain) {
	// This function matches a wildcard domain against a normal domain
   const char s[2] = ".";
   char *wildcard_split;
   int wildcard_size = 0;
   char *domain_split;
   int domain_size = 0;

	/* get the first token */
	wildcard_split = strtok(wildcard_domain, s);

	/* walk through other tokens */
	while(wildcard_split != NULL) {
	  printf(" %s\n", wildcard_split);

	  wildcard_split = strtok(NULL, s);
	  wildcard_size++;
	}
	/* get the first token */
	domain_split = strtok(domain_split, s);

	/* walk through other tokens */
	while(domain_split != NULL) {
	  printf(" %s\n", domain_split);

	  domain_split = strtok(NULL, s);
	  domain_size++;
	}

	if (wildcard_size != domain_size) {
		return FALSE;
	} 
	return TRUE;
	// for (int sector = 0; sector < wildcard_size; sector++) {
	// 	int wild_count = 0;
	// 	for (int chr = 0; chr < strlen(wildcard_split[sector]); chr++) {
	// 		if (wildcard_split[sector][chr]) {
	// 			wild_count++;
	// 		}
	// 		if ((wildcard_split[sector][chr] != domain_split[sector][chr]) &&
	// 			(wild_count < 1) || wild_count > 1){
	// 			return FALSE;
	// 		}
	// 	}
	// }
	// return TRUE;

}


int check_domain(X509 *cert, char* domain) {
	// This function checks if the domain name is valid

    int valid = TRUE;

    

    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    printf("Extension:%s\n", buff);

    BUF_MEM *bptr = NULL;
    char *buf = NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    //bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    //Can print or parse value
    printf("%s\n", buf);
    
    BIO_free_all(bio);
    free(buf);

    return 0;
}