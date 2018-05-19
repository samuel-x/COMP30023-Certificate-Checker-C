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

#define WILDCARD '*'
#define SPACE ' '
#define COMMA ','
#define LABEL_SEPARATOR '.'
#define TEST_DIR "./sample_certs/"
#define RSA_LENGTH 2048
#define BITS 8
#define CA_PRUNE 3

#define BASICCONSTRAINTS "X509v3 Basic Constraints"
#define EXTUSAGE "X509v3 Extended Key Usage"
#define SAN "X509v3 Subject Alternative Name"
#define TLS "TLS Web Server Authentication"

#define PRINT_LINE printf("----------------------------------------------\n");

#define TRUE 1
#define FALSE 0
#define TRUE_STR "TRUE"
#define FALSE_STR "FALSE"

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
int check_RSA_length(X509 *cert);
int check_domains(char* alt_names, char* domain);
int check_SAN(X509 *cert, char* domain);
int check_basic_constraints(X509 *cert);
int check_TLS(X509 *cert);
char *remove_comma(char *str);

int main(int argc, const char *argv[])
{
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;

    X509_CINF *cert_inf = NULL;
    int valid = TRUE;

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
		PRINT_LINE;
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
	    // Now check our subject alt domain names
	    // If there isn't a SAN provided, fallback to the original subject CN
	    if(!check_SAN(cert, domain)) {
			if(!check_subject(cert, domain)) {
				valid = FALSE;
			};
	    }

	    // Check our RSA is of length 2048
	    if (!check_RSA_length(cert)) {
	    	valid = FALSE;
	    }

	    // Check for correct key usage
	    if (!check_basic_constraints(cert)) {
	    	valid = FALSE;
	    }
	    if (!check_TLS(cert)) {
	    	valid = FALSE;
	    }

	    if(valid) {
	    	printf(MAG "\nThis certificate is valid!\n\n" RES);
	    }
	    else {
	    	printf(RED "\nThis certificate is not valid.\n\n" RES);
	    }

		output = (char *)safe_malloc(sizeof(char) * (strlen(certificate_path)+strlen(domain)+4));

		sprintf(output, "%s,%s,%d\n", certificate_path, domain, valid);
	    fprintf(out, "%s", output);

	    memset(domain, 0, 256);
	    memset(certificate_path, 0, 256);
	}

    //*********************
    // End of Example code
    //*********************

	free(path);
	free(output);
	X509_free(cert);
	BIO_free_all(certificate_bio);
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
	int valid = TRUE;

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
 		valid = FALSE;
 	}

 	// Check if we are before the due date
 	if (!ASN1_TIME_diff(&diff_day, &diff_sec, NULL, valid_to)) {
        fprintf(stderr, "Error comparing validity dates in certificate.\n");
        exit(EXIT_FAILURE);
 	}
 	if (diff_day < 0 || diff_sec < 0) {
 		printf(RED "This certificate's notafter date is not valid\n" RES);
 		valid = FALSE;
 	}

	printf(GRE "This certificate's date is valid!\n\n" RES);
	return valid;
}


int check_subject(X509 *cert, char* domain) {
	X509_NAME *subject_issuer = NULL;
    subject_issuer = X509_get_subject_name(cert);

    ASN1_STRING *subject_domain;
    char *subject_domain_str = safe_malloc(sizeof(char) * strlen(domain));
	X509_NAME_ENTRY *e;

	printf("Checking subject domain...\n");
	e = X509_NAME_get_entry(subject_issuer, 5);
	subject_domain = X509_NAME_ENTRY_get_data(e);
	ASN1_STRING_print_ex_fp(stdout, subject_domain, 1);
	printf("\n");

	subject_domain_str = (char *)ASN1_STRING_data(subject_domain);
	if (contains_wildcard(subject_domain_str)) {
		return wildcard_match(subject_domain_str, domain);
	}
	else {
		if (strcmp(subject_domain_str, domain) != 0) {
			printf(RED "%s and %s are not the same!\n\n" RES, subject_domain_str, domain);
			return FALSE;
		}
		else{
			printf(GRE "%s and %s are the same!\n\n" RES, subject_domain_str, domain);
			return TRUE;
		}
	}	
}

int check_domains(char* alt_names, char* domain) {

	printf(CYA "Checking domains %s\n", alt_names);

	const char s[5] = "DNS:";
	char *alt_names_split;
	char *test_domains[256];
	char *test_domain;
	int alt_names_len = 0;
	int valid = FALSE;

	/* get the first token */
	alt_names_split = strtok(alt_names, "DNS:");

	/* walk through other tokens */
	while(alt_names_split != NULL) {
		
		test_domains[alt_names_len] = strdup(alt_names_split);
		printf("Strtok %d: %s\n", alt_names_len, alt_names_split);
		alt_names_split = strtok(NULL, s);
		alt_names_len++;
	}

	for (int i = 0; i < alt_names_len && valid == FALSE; i++) {
		test_domain = remove_comma(test_domains[i]);

		printf("Domain %d: %s\n", i, test_domain);

		if (contains_wildcard(test_domain)) {
			valid = wildcard_match(test_domain, domain);
		}
		else {
			if (strcmp(test_domain, domain) != 0) {
				printf(RED "%s and %s are not the same!\n" RES, test_domain, domain);
				valid = FALSE;
			}
			else{
				printf(GRE "%s and %s are the same!\n" RES, test_domain, domain);
				valid = TRUE;
			}
		}

	}

	return valid;

}

char *remove_comma(char *str) {
	printf("Removing comma of %s...\n", str);
	char *cpy_str = safe_malloc(sizeof(char)*strlen(str));
	char *new_str = safe_malloc(sizeof(char)*strlen(str));
	int new_str_len = 0;

	strcpy(cpy_str, str);
	for (int i = 0; i < strlen(cpy_str); i++) {
		if (cpy_str[i] != COMMA && cpy_str[i] != SPACE) {
			new_str[new_str_len] = cpy_str[i];
			new_str_len++;
		}
	}
	new_str[new_str_len] = '\0';
	free(cpy_str);
	return new_str;
}

int contains_wildcard(char* domain) {
	// This function checks if the domain has a wildcard inside
	printf("Checking %s for wildcards...\n", domain);
	for (int i = 0; i < strlen(domain) && domain[i] != LABEL_SEPARATOR; i++) {
		if (domain[i] == WILDCARD) {
			printf(GRE "Wildcard found!\n" RES);
			return TRUE;
		}
	}
	printf(RED "No wildcards, continue checking domains\n" RES);
	return FALSE;
}

int wildcard_match(char* wildcard_domain, char* domain) {
	// This function matches a wildcard domain against a normal domain
	printf("Matching wildcard...\n");
	const char s[2] = ".";
	char *domain1 = strdup(wildcard_domain);
	char *domain2 = strdup(domain);
	char *wildcard_split;
	int wildcard_size = 0;
	char *domain_split;
	int domain_size = 0;

	/* get the first token */
	wildcard_split = strtok(domain1, s);

	/* walk through other tokens */
	while(wildcard_split != NULL) {
		printf("Wildcard Checking %d: %s\n", wildcard_size, wildcard_split);
		wildcard_split = strtok(NULL, s);
		wildcard_size++;
	}
	/* get the first token */
	domain_split = strtok(domain2, s);

	/* walk through other tokens */
	while(domain_split != NULL) {
		printf("Domain Checking %d: %s\n", domain_size, domain_split);
		domain_split = strtok(NULL, s);
		domain_size++;
	}

	if (wildcard_size != domain_size) {
		printf(RED "This Wildcard %s does not match %s\n" RES, wildcard_domain, domain);
		return FALSE;
	}
	printf(GRE "This Wildcard %s matches %s!\n" RES, wildcard_domain, domain);
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

int check_SAN(X509 *cert, char* domain) {
	// This function checks if the domain name is valid

	printf(CYA "Checking SAN names...\n" RES);
    int valid = TRUE;
    int ext_index = 0;

    // Check if any SANs exist. If they do, check each domain.
    ext_index = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    printf("Index for SAN: %d\n", ext_index);
    if (ext_index < 0) {
    	printf(YEL "No SANs to check, checking subject...\n" RES);
    	return FALSE;
    }

    // Otherwise, get our SANs
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_alt_name, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    
    // Check we have the correct extention
    if (strcmp(buff, SAN) != 0) {
    	printf(RED "Incorrect extension given.\n" RES);
    	return FALSE;
    }

    // Get our extension value
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

    //Parse our SANs and check each domain
    valid = check_domains(buf, domain);
    
    BIO_free_all(bio);
    free(buf);

    return valid;
}

int check_RSA_length(X509 *cert) {

	printf(CYA "Checking if the length of the RSA key is at least 2048...\n" RES);

	EVP_PKEY * public_key = X509_get_pubkey(cert);
	RSA *rsa_key = EVP_PKEY_get1_RSA(public_key);
	int key_length = RSA_size(rsa_key)*BITS;
	RSA_free(rsa_key);

	if (key_length < RSA_LENGTH) {
		printf(RED "This certificate's RSA length %d is too short!\n" RES, key_length);
		return FALSE;
	}
	printf(GRE "This certificate's RSA length %d is sufficient!\n" RES, key_length);

	return TRUE;
}

int check_basic_constraints(X509 *cert) {
	int has_basic_constraints = FALSE;

    // Check for basic constraints
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_basic_constraints, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    printf("%s\n", buff);
    // Check we have the correct extention
    if (strcmp(buff, BASICCONSTRAINTS) != 0) {
    	printf(RED "Incorrect extension given.\n" RES);
    	return FALSE;
    }

    // Get our extension value
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

    // Check whether basic_constraints is true
    char *basic_constraint = buf + CA_PRUNE;

    printf("%s\n", basic_constraint);
    if (strcmp(basic_constraint, FALSE_STR) == 0) {
    	printf(GRE "This certificate has basic constraints!\n" RES);
    	has_basic_constraints = TRUE;
    }
    else {
    	printf(RED "This certificate does not have basic constraints!\n" RES);
    	has_basic_constraints = FALSE;
    }
    return has_basic_constraints;
}

int check_TLS(X509 *cert) {
	int has_TLS = FALSE;

    // Check for basic constraints
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    printf("%s\n", buff);
    // Check we have the correct extention
    if (strcmp(buff, EXTUSAGE) != 0) {
    	printf(RED "Incorrect extension given.\n" RES);
    	return FALSE;
    }

    // Get our extension value
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

    printf("%s\n", buf);

    const char s[2] = ",";
    char *server_auth;

    server_auth = strtok(buf, s);
    while (server_auth != NULL) {
	    if (strcmp(buf, TLS) == 0) {
	    	printf(GRE "This certificate has TLS!\n" RES);
	    	has_TLS = TRUE;
	    }
	    else {
	    	printf(RED "This certificate does not have TLS!\n" RES);
	    	has_TLS = FALSE;
	    }
	    server_auth = strtok(NULL, s);
	}
    return has_TLS;
}

