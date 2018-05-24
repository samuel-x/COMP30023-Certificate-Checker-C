/*  Computer Systems COMP30023 Part B
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

// Import our Libraries
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// Define some character constants
#define WILDCARD '*'
#define SPACE ' '
#define COMMA ','
#define LABEL_SEPARATOR '.'
#define COMMA_STR ","
#define DNS_SEPARATOR "DNS:"
#define DOT_STR "."

// Define our numeric constants
#define RSA_LENGTH 2048
#define BITS 8
#define CA_PRUNE 3
#define BUFFER_SIZE 256
#define SUFFIX_SIZE 4
#define CA_LEN 10
#define START_DOMAIN 0

// Define our extension names for checking
#define BASICCONSTRAINTS "X509v3 Basic Constraints"
#define EXTUSAGE "X509v3 Extended Key Usage"
#define SAN "X509v3 Subject Alternative Name"
#define TLS "TLS Web Server Authentication"

// Define True and False values
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
int compare_domain(char* cert_domain, char* domain);
int check_domains(char* alt_names, char* domain);
int check_SAN(X509 *cert, char* domain);
int check_basic_constraints(X509 *cert);
int check_TLS(X509 *cert);
char *remove_comma(char *str);
char *get_ext_string(X509 *cert, int nid);

int main(int argc, const char *argv[])
{
	// Define our variables
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_CINF *cert_inf = NULL;
    int valid = TRUE;

    // Read in our CSV and prepare a file to be written to
    FILE *in = fopen(argv[1], "r");
    FILE *out = fopen("output.csv", "w");
    char domain[BUFFER_SIZE];
    char certificate_path[BUFFER_SIZE];
    char *output = safe_malloc(sizeof(char) * BUFFER_SIZE);

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    // Scan the CSV for a line. If there is still text to be read, 
    // read the line into certificate_path (the certificate to check) 
    // and domain (the domain to check the certificate against)
    while (fscanf(in, "%30[^ ,\n\t],%s\n", certificate_path, domain) > 0) {
	    // Read certificate into BIO
    	// Note: this is taken from the Assignment 2 sample code
	    if (!(BIO_read_filename(certificate_bio, certificate_path)))
	    {
	        fprintf(stderr, "Error in reading cert BIO filename\n");
	        exit(EXIT_FAILURE);
	    }
	    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
	    {
	        fprintf(stderr, "Error in loading certificate\n");
	        exit(EXIT_FAILURE);
	    }
	    // Here we check our certificate for the constraints as specified
	    // in the spec.
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

	    // Check for correct key usage (Basic Constraints and TLS)
	    if (!check_basic_constraints(cert)) {
	    	valid = FALSE;
	    }
	    if (!check_TLS(cert)) {
	    	valid = FALSE;
	    }

	    // Malloc the string for output.csv
		output = (char *)safe_malloc(sizeof(char) 
					* (strlen(certificate_path)+strlen(domain)+SUFFIX_SIZE));

		// Print our output to output.csv
		sprintf(output, "%s,%s,%d\n", certificate_path, domain, valid);
	    fprintf(out, "%s", output);

	    // Reset our strings
	    memset(domain, 0, BUFFER_SIZE);
	    memset(certificate_path, 0, BUFFER_SIZE);
	}

	// Free everything and close our files.
	free(output);
	X509_free(cert);
	BIO_free_all(certificate_bio);
    fclose(in);
    fclose(out);
    exit(0);
}

int check_time(X509_CINF *info) {
	// This method checks if a certificate is still valid according to
	// the "after" and "before" times specified on the certificate
	// Define our variables
	const ASN1_TIME *valid_from;
	const ASN1_TIME *valid_to;
	int diff_day, diff_sec;
	int valid = TRUE;

	// Get our validity dates
	valid_from = info->validity->notBefore;
	valid_to = info->validity->notAfter;

	// Check if we are past the issue date
	// Note: When NULL is passed into ASN1_TIME_diff it will use the 
	// 		computer's current time
 	if (!ASN1_TIME_diff(&diff_day, &diff_sec, valid_from, NULL)) {
        exit(EXIT_FAILURE);
 	}
 	if (diff_day < 0 || diff_sec < 0) {
 		valid = FALSE;
 	}

 	// Check if we are before the due date
 	if (!ASN1_TIME_diff(&diff_day, &diff_sec, NULL, valid_to)) {
        exit(EXIT_FAILURE);
 	}
 	if (diff_day < 0 || diff_sec < 0) {
 		valid = FALSE;
 	}

	return valid;
}


int check_subject(X509 *cert, char* domain) {
	// This function checks if the subject domain is valid
	// Get our subject
	X509_NAME *subject_issuer = NULL;
    subject_issuer = X509_get_subject_name(cert);
    char *domain_cpy = strdup(domain);

    // Define some valiues
    ASN1_STRING *subject_domain;
    char *subject_domain_str = safe_malloc(sizeof(char) * strlen(domain));
	X509_NAME_ENTRY *e;

	// Now get our domain to check against
	e = X509_NAME_get_entry(subject_issuer, 5);
	subject_domain = X509_NAME_ENTRY_get_data(e);

	// Convert the ASN1 String into a regular string and check the domain
	subject_domain_str = (char *)ASN1_STRING_data(subject_domain);
	return compare_domain(subject_domain_str, domain_cpy);
}

int compare_domain(char* cert_domain, char* domain) {
	// This function takes two domains and checks if they match

	// First check for wildcards, otherwise, just compare the strings
	if (contains_wildcard(cert_domain)) {
		return wildcard_match(cert_domain, domain);
	}
	else {
		if (strcmp(cert_domain, domain) != 0) {
			return FALSE;
		}
		else{
			return TRUE;
		}
	}
}

int check_domains(char* alt_names, char* domain) {
	// This function checks if a series of SAN domains are valid
	// Define our variables
	char *alt_names_split;
	char *test_domains[BUFFER_SIZE];
	char *test_domain;
	int alt_names_len = 0;
	int valid = FALSE;

	// Use strtok, get our first SAN
	alt_names_split = strtok(alt_names, DNS_SEPARATOR);

	// Append all SANs to an array for checking
	while(alt_names_split != NULL) {
		
		test_domains[alt_names_len] = strdup(alt_names_split);
		alt_names_split = strtok(NULL, DNS_SEPARATOR);
		alt_names_len++;
	}

	// Iterate through all domains and check if they are valid
	// If one is valid, stop checking for further domains and return
	for (int i = 0; i < alt_names_len && valid == FALSE; i++) {
		test_domain = remove_comma(test_domains[i]);

		compare_domain(test_domain, domain);

	}

	return valid;

}

char *remove_comma(char *str) {
	// This function simply removes the end comma from a domain (in the SAN
	// format)
	char *cpy_str = safe_malloc(sizeof(char)*strlen(str));
	char *new_str = safe_malloc(sizeof(char)*strlen(str));
	int new_str_len = 0;

	// Make a new copy of the string
	// Note: This was done to prevent strange behaviour with strtok
	strcpy(cpy_str, str);

	// Iterate through the new string and add all characters that are not c
	// commas or spaces
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
	// Iterate through the first part of the domain.
	// If it is a wildcard charcter, then this is a wildcard domain

	// Note: As specified here en.wikipedia.org/wiki/Wildcard_certificate
	// 		A wildcard character not in the first label is illegal, as such
	// 		do not check further than the first part of the domain
	for (int i = 0; i < strlen(domain) && domain[i] != LABEL_SEPARATOR; i++) {
		if (domain[i] == WILDCARD) {
			return TRUE;
		}
	}
	return FALSE;
}

int wildcard_match(char* wildcard_domain, char* domain) {
	// This function matches a wildcard domain against a normal domain
	char *wildcard_domains[BUFFER_SIZE];
	char *check_domains[BUFFER_SIZE];
	char *wildcard_split;
	int wildcard_size = 0;
	char *domain_split;
	int domain_size = 0;

	// Start strtok for wildcard domain
	wildcard_split = strtok(wildcard_domain, DOT_STR);

	// We'll walk through each part of the label and add it to an array
	// for later analysis 
	while(wildcard_split != NULL) {
		wildcard_domains[wildcard_size] = strdup(wildcard_split);
		wildcard_split = strtok(NULL, DOT_STR);
		wildcard_size++;
	}

	// Repeat the same as above with the domain we are checking against
	domain_split = strtok(domain, DOT_STR);
	while(domain_split != NULL) {
		check_domains[domain_size] = strdup(domain_split);
		domain_split = strtok(NULL, DOT_STR);
		domain_size++;
	}

	// If the two domains do not have the same number of labels then something
	// is wrong
	if (wildcard_size != domain_size) {
		return FALSE;
	}

	// Iterate through the first part of the label 
	// If they do not match up to the wildcard then return a false
	for (int chr = 0; chr < strlen(wildcard_domains[START_DOMAIN]); chr++) {
		if (wildcard_domains[START_DOMAIN][chr] != WILDCARD &&
			wildcard_domains[START_DOMAIN][chr] != 
			check_domains[START_DOMAIN][chr]) {
			return FALSE;
		}
	}

	// Then check the remaining labels if they match
	for (int sector = 1; sector < wildcard_size; sector++) {
		if (strcmp(wildcard_domains[sector], check_domains[sector]) != 0) {
			return FALSE;
		}
	}
	return TRUE;

}

int check_SAN(X509 *cert, char* domain) {
	// This function checks if the subject alternative names contain
	// a valid domain
    int valid = TRUE;
    int ext_index = 0;
    char *domain_cpy = strdup(domain);

    // Check if any SANs exist. If they do, check each domain
    ext_index = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (ext_index < 0) {
    	return FALSE;
    }

    char *subject_alt_names = get_ext_string(cert, NID_subject_alt_name);

    //Parse our SANs and check each domain
    valid = check_domains(subject_alt_names, domain_cpy);

    return valid;
}

int check_RSA_length(X509 *cert) {
	// This function checks if the key has a valid RSA key length
	// Get our key and find the number of bytes
	EVP_PKEY * public_key = X509_get_pubkey(cert);
	RSA *rsa_key = EVP_PKEY_get1_RSA(public_key);
	int key_length = RSA_size(rsa_key) * BITS;

	// Free our key, we already have the length
	RSA_free(rsa_key);

	if (key_length < RSA_LENGTH) {
		return FALSE;
	}

	return TRUE;
}

int check_basic_constraints(X509 *cert) {
	// This checks for basic constraints in our certificate
    // Get our basic constraints and then prune the "CA:" part of the string
    char *basic_constraint = safe_malloc(sizeof(char) * CA_LEN);
    basic_constraint = get_ext_string(cert, 
    							NID_basic_constraints) + CA_PRUNE;

    // Then, check whether basic_constraints is false
    if (strcmp(basic_constraint, FALSE_STR) == 0) {
    	return TRUE;
    }
    return FALSE;
}

int check_TLS(X509 *cert) {
	// This function checks if the certificate has TLS server authentication

	char *TLS_attr = safe_malloc(sizeof(char) * BUFFER_SIZE);
	char *authentications[BUFFER_SIZE];
	int authentications_size = 0;
	// Get our key usage values
	TLS_attr = get_ext_string(cert, NID_ext_key_usage);
    char *server_auth;

    // Strtok through our values (separated by commas) and add them to an array
    server_auth = strtok(TLS_attr, COMMA_STR);
    // Check the first value for whether it has TLS or not
    if (strcmp(server_auth, TLS) == 0) {
    	return TRUE;
    }

    // If there are more values, then add them to an array of strings
    // for checking
    while (server_auth != NULL) {
	    authentications[authentications_size] = strdup(server_auth);
	    authentications_size++;
	    server_auth = strtok(NULL, COMMA_STR);
	}

	// Check 'em
	// Check if TLS exists
	for (int i = 1; i < authentications_size; i++) {
	    if (strcmp(authentications[i] + 1, TLS) == 0) {
	    	return TRUE;
	    }
	}

    return FALSE;
}


char *get_ext_string(X509 *cert, int nid) {
    // This function gets an extension in string for with a provided nid
	// Note: This is adapted from the sample Assignment2 repository provided
	// for the assignment.
    X509_EXTENSION *ex = X509_get_ext(cert, 
    					 X509_get_ext_by_NID(cert, nid, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);

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
    buf = (char *)safe_malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    BIO_free_all(bio);
    return buf;
}
