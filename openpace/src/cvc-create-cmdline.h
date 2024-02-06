/** @file cvc-create-cmdline.h
 *  @brief The header file for the command line option parser
 *  generated by GNU Gengetopt version 2.22.6
 *  http://www.gnu.org/software/gengetopt.
 *  DO NOT modify this file, since it can be overwritten
 *  @author GNU Gengetopt by Lorenzo Bettini */

#ifndef CVC_CREATE_CMDLINE_H
#define CVC_CREATE_CMDLINE_H

/* If we use autoconf.  */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h> /* for FILE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef CMDLINE_PARSER_PACKAGE
/** @brief the program name (used for printing errors) */
#define CMDLINE_PARSER_PACKAGE "cvc-create"
#endif

#ifndef CMDLINE_PARSER_PACKAGE_NAME
/** @brief the complete program name (used for help and version) */
#define CMDLINE_PARSER_PACKAGE_NAME "cvc-create"
#endif

#ifndef CMDLINE_PARSER_VERSION
/** @brief the program version */
#define CMDLINE_PARSER_VERSION VERSION
#endif

enum enum_role { role__NULL = -1, role_arg_cvca = 0, role_arg_dv_domestic, role_arg_dv_foreign, role_arg_terminal };
enum enum_type { type__NULL = -1, type_arg_at = 0, type_arg_is, type_arg_st, type_arg_derived_from_signer };
enum enum_scheme { scheme__NULL = -1, scheme_arg_ECDSA_SHA_1 = 0, scheme_arg_ECDSA_SHA_224, scheme_arg_ECDSA_SHA_256, scheme_arg_ECDSA_SHA_384, scheme_arg_ECDSA_SHA_512, scheme_arg_RSA_v1_5_SHA_1, scheme_arg_RSA_v1_5_SHA_256, scheme_arg_RSA_v1_5_SHA_512, scheme_arg_RSA_PSS_SHA_1, scheme_arg_RSA_PSS_SHA_256, scheme_arg_RSA_PSS_SHA_512 };

/** @brief Where the command line options are stored */
struct gengetopt_args_info
{
  const char *help_help; /**< @brief Print help and exit help description.  */
  const char *version_help; /**< @brief Print version and exit help description.  */
  char * out_cert_arg;	/**< @brief Where to save the certificate (default='CHR.cvcert').  */
  char * out_cert_orig;	/**< @brief Where to save the certificate original value given at command line.  */
  const char *out_cert_help; /**< @brief Where to save the certificate help description.  */
  enum enum_role role_arg;	/**< @brief The terminal's role.  */
  char * role_orig;	/**< @brief The terminal's role original value given at command line.  */
  const char *role_help; /**< @brief The terminal's role help description.  */
  enum enum_type type_arg;	/**< @brief Type of the terminal (Authentication Terminal, Inspection System or Signature Terminal) (default='derived_from_signer').  */
  char * type_orig;	/**< @brief Type of the terminal (Authentication Terminal, Inspection System or Signature Terminal) original value given at command line.  */
  const char *type_help; /**< @brief Type of the terminal (Authentication Terminal, Inspection System or Signature Terminal) help description.  */
  char * issued_arg;	/**< @brief Date the certificate was issued (default='today').  */
  char * issued_orig;	/**< @brief Date the certificate was issued original value given at command line.  */
  const char *issued_help; /**< @brief Date the certificate was issued help description.  */
  char * expires_arg;	/**< @brief Date until the certicate is valid.  */
  char * expires_orig;	/**< @brief Date until the certicate is valid original value given at command line.  */
  const char *expires_help; /**< @brief Date until the certicate is valid help description.  */
  char * sign_with_arg;	/**< @brief Private key for signing the new certificate.  */
  char * sign_with_orig;	/**< @brief Private key for signing the new certificate original value given at command line.  */
  const char *sign_with_help; /**< @brief Private key for signing the new certificate help description.  */
  enum enum_scheme scheme_arg;	/**< @brief Signature scheme that the new terminal will use.  */
  char * scheme_orig;	/**< @brief Signature scheme that the new terminal will use original value given at command line.  */
  const char *scheme_help; /**< @brief Signature scheme that the new terminal will use help description.  */
  char * csr_arg;	/**< @brief Certificate signing request with the attributes.  */
  char * csr_orig;	/**< @brief Certificate signing request with the attributes original value given at command line.  */
  const char *csr_help; /**< @brief Certificate signing request with the attributes help description.  */
  char * chr_arg;	/**< @brief Certificate holder reference (2 characters ISO 3166-1 ALPHA-2 country code, 0-9 characters ISO/IEC 8859-1 holder mnemonic, 5 characters ISO/IEC 8859-1 numeric or alphanumeric sequence number).  */
  char * chr_orig;	/**< @brief Certificate holder reference (2 characters ISO 3166-1 ALPHA-2 country code, 0-9 characters ISO/IEC 8859-1 holder mnemonic, 5 characters ISO/IEC 8859-1 numeric or alphanumeric sequence number) original value given at command line.  */
  const char *chr_help; /**< @brief Certificate holder reference (2 characters ISO 3166-1 ALPHA-2 country code, 0-9 characters ISO/IEC 8859-1 holder mnemonic, 5 characters ISO/IEC 8859-1 numeric or alphanumeric sequence number) help description.  */
  char * sign_as_arg;	/**< @brief CV certificate of the entity signing the new certificate (default='self signed').  */
  char * sign_as_orig;	/**< @brief CV certificate of the entity signing the new certificate original value given at command line.  */
  const char *sign_as_help; /**< @brief CV certificate of the entity signing the new certificate help description.  */
  char * key_arg;	/**< @brief Private key of the Terminal (default='derived from signer').  */
  char * key_orig;	/**< @brief Private key of the Terminal original value given at command line.  */
  const char *key_help; /**< @brief Private key of the Terminal help description.  */
  char * out_key_arg;	/**< @brief Where to save the derived private key (default='CHR.pkcs8').  */
  char * out_key_orig;	/**< @brief Where to save the derived private key original value given at command line.  */
  const char *out_key_help; /**< @brief Where to save the derived private key help description.  */
  char * out_desc_arg;	/**< @brief Where to save the encoded certificate description (default='CHR.desc').  */
  char * out_desc_orig;	/**< @brief Where to save the encoded certificate description original value given at command line.  */
  const char *out_desc_help; /**< @brief Where to save the encoded certificate description help description.  */
  char * cert_desc_arg;	/**< @brief Terms of usage as part of the certificate description (*.txt, *.html or *.pdf).  */
  char * cert_desc_orig;	/**< @brief Terms of usage as part of the certificate description (*.txt, *.html or *.pdf) original value given at command line.  */
  const char *cert_desc_help; /**< @brief Terms of usage as part of the certificate description (*.txt, *.html or *.pdf) help description.  */
  char * issuer_name_arg;	/**< @brief Name of the issuer of this certificate (certificate description).  */
  char * issuer_name_orig;	/**< @brief Name of the issuer of this certificate (certificate description) original value given at command line.  */
  const char *issuer_name_help; /**< @brief Name of the issuer of this certificate (certificate description) help description.  */
  char * issuer_url_arg;	/**< @brief URL that points to informations about the issuer of this certificate (certificate description).  */
  char * issuer_url_orig;	/**< @brief URL that points to informations about the issuer of this certificate (certificate description) original value given at command line.  */
  const char *issuer_url_help; /**< @brief URL that points to informations about the issuer of this certificate (certificate description) help description.  */
  char * subject_name_arg;	/**< @brief Name of the holder of this certificate (certificate description).  */
  char * subject_name_orig;	/**< @brief Name of the holder of this certificate (certificate description) original value given at command line.  */
  const char *subject_name_help; /**< @brief Name of the holder of this certificate (certificate description) help description.  */
  char * subject_url_arg;	/**< @brief URL that points to informations about the subject of this certificate (certificate description).  */
  char * subject_url_orig;	/**< @brief URL that points to informations about the subject of this certificate (certificate description) original value given at command line.  */
  const char *subject_url_help; /**< @brief URL that points to informations about the subject of this certificate (certificate description) help description.  */
  int write_dg17_flag;	/**< @brief Allow writing DG 17 (Normal Place of Residence) (default=off).  */
  const char *write_dg17_help; /**< @brief Allow writing DG 17 (Normal Place of Residence) help description.  */
  int write_dg18_flag;	/**< @brief Allow writing DG 18 (Community ID) (default=off).  */
  const char *write_dg18_help; /**< @brief Allow writing DG 18 (Community ID) help description.  */
  int write_dg19_flag;	/**< @brief Allow writing DG 19 (Residence Permit I) (default=off).  */
  const char *write_dg19_help; /**< @brief Allow writing DG 19 (Residence Permit I) help description.  */
  int write_dg20_flag;	/**< @brief Allow writing DG 20 (Residence Permit II) (default=off).  */
  const char *write_dg20_help; /**< @brief Allow writing DG 20 (Residence Permit II) help description.  */
  int write_dg21_flag;	/**< @brief Allow writing DG 21 (Optional Data) (default=off).  */
  const char *write_dg21_help; /**< @brief Allow writing DG 21 (Optional Data) help description.  */
  int at_rfu32_flag;	/**< @brief Allow RFU R/W Access bit 32 (default=off).  */
  const char *at_rfu32_help; /**< @brief Allow RFU R/W Access bit 32 help description.  */
  int at_rfu31_flag;	/**< @brief Allow RFU R/W Access bit 31 (default=off).  */
  const char *at_rfu31_help; /**< @brief Allow RFU R/W Access bit 31 help description.  */
  int at_rfu30_flag;	/**< @brief Allow RFU R/W Access bit 30 (default=off).  */
  const char *at_rfu30_help; /**< @brief Allow RFU R/W Access bit 30 help description.  */
  int at_rfu29_flag;	/**< @brief Allow RFU R/W Access bit 29 (default=off).  */
  const char *at_rfu29_help; /**< @brief Allow RFU R/W Access bit 29 help description.  */
  int read_dg1_flag;	/**< @brief Allow reading DG 1   (Document Type) (default=off).  */
  const char *read_dg1_help; /**< @brief Allow reading DG 1   (Document Type) help description.  */
  int read_dg2_flag;	/**< @brief Allow reading DG 2   (Issuing State) (default=off).  */
  const char *read_dg2_help; /**< @brief Allow reading DG 2   (Issuing State) help description.  */
  int read_dg3_flag;	/**< @brief Allow reading DG 3   (Date of Expiry) (default=off).  */
  const char *read_dg3_help; /**< @brief Allow reading DG 3   (Date of Expiry) help description.  */
  int read_dg4_flag;	/**< @brief Allow reading DG 4   (Given Names) (default=off).  */
  const char *read_dg4_help; /**< @brief Allow reading DG 4   (Given Names) help description.  */
  int read_dg5_flag;	/**< @brief Allow reading DG 5   (Family Names) (default=off).  */
  const char *read_dg5_help; /**< @brief Allow reading DG 5   (Family Names) help description.  */
  int read_dg6_flag;	/**< @brief Allow reading DG 6   (Religious/Artistic Name) (default=off).  */
  const char *read_dg6_help; /**< @brief Allow reading DG 6   (Religious/Artistic Name) help description.  */
  int read_dg7_flag;	/**< @brief Allow reading DG 7   (Academic Title) (default=off).  */
  const char *read_dg7_help; /**< @brief Allow reading DG 7   (Academic Title) help description.  */
  int read_dg8_flag;	/**< @brief Allow reading DG 8   (Date of Birth) (default=off).  */
  const char *read_dg8_help; /**< @brief Allow reading DG 8   (Date of Birth) help description.  */
  int read_dg9_flag;	/**< @brief Allow reading DG 9   (Place of Birth) (default=off).  */
  const char *read_dg9_help; /**< @brief Allow reading DG 9   (Place of Birth) help description.  */
  int read_dg10_flag;	/**< @brief Allow reading DG 10  (Nationality) (default=off).  */
  const char *read_dg10_help; /**< @brief Allow reading DG 10  (Nationality) help description.  */
  int read_dg11_flag;	/**< @brief Allow reading DG 11  (Sex) (default=off).  */
  const char *read_dg11_help; /**< @brief Allow reading DG 11  (Sex) help description.  */
  int read_dg12_flag;	/**< @brief Allow reading DG 12  (Optional Data) (default=off).  */
  const char *read_dg12_help; /**< @brief Allow reading DG 12  (Optional Data) help description.  */
  int read_dg13_flag;	/**< @brief Allow reading DG 13 (default=off).  */
  const char *read_dg13_help; /**< @brief Allow reading DG 13 help description.  */
  int read_dg14_flag;	/**< @brief Allow reading DG 14 (default=off).  */
  const char *read_dg14_help; /**< @brief Allow reading DG 14 help description.  */
  int read_dg15_flag;	/**< @brief Allow reading DG 15 (default=off).  */
  const char *read_dg15_help; /**< @brief Allow reading DG 15 help description.  */
  int read_dg16_flag;	/**< @brief Allow reading DG 16 (default=off).  */
  const char *read_dg16_help; /**< @brief Allow reading DG 16 help description.  */
  int read_dg17_flag;	/**< @brief Allow reading DG 17  (Normal Place of Residence) (default=off).  */
  const char *read_dg17_help; /**< @brief Allow reading DG 17  (Normal Place of Residence) help description.  */
  int read_dg18_flag;	/**< @brief Allow reading DG 18  (Community ID) (default=off).  */
  const char *read_dg18_help; /**< @brief Allow reading DG 18  (Community ID) help description.  */
  int read_dg19_flag;	/**< @brief Allow reading DG 19  (Residence Permit I) (default=off).  */
  const char *read_dg19_help; /**< @brief Allow reading DG 19  (Residence Permit I) help description.  */
  int read_dg20_flag;	/**< @brief Allow reading DG 20  (Residence Permit II) (default=off).  */
  const char *read_dg20_help; /**< @brief Allow reading DG 20  (Residence Permit II) help description.  */
  int read_dg21_flag;	/**< @brief Allow reading DG 21  (Optional Data) (default=off).  */
  const char *read_dg21_help; /**< @brief Allow reading DG 21  (Optional Data) help description.  */
  int install_qual_cert_flag;	/**< @brief Allow installing qualified certificate (default=off).  */
  const char *install_qual_cert_help; /**< @brief Allow installing qualified certificate help description.  */
  int install_cert_flag;	/**< @brief Allow installing certificate (default=off).  */
  const char *install_cert_help; /**< @brief Allow installing certificate help description.  */
  int pin_management_flag;	/**< @brief Allow PIN management (default=off).  */
  const char *pin_management_help; /**< @brief Allow PIN management help description.  */
  int can_allowed_flag;	/**< @brief CAN allowed (default=off).  */
  const char *can_allowed_help; /**< @brief CAN allowed help description.  */
  int privileged_flag;	/**< @brief Privileged terminal (default=off).  */
  const char *privileged_help; /**< @brief Privileged terminal help description.  */
  int rid_flag;	/**< @brief Allow restricted identification (default=off).  */
  const char *rid_help; /**< @brief Allow restricted identification help description.  */
  int verify_community_flag;	/**< @brief Allow community ID verification (default=off).  */
  const char *verify_community_help; /**< @brief Allow community ID verification help description.  */
  int verify_age_flag;	/**< @brief Allow age verification (default=off).  */
  const char *verify_age_help; /**< @brief Allow age verification help description.  */
  int st_rfu5_flag;	/**< @brief Allow RFU bit 5 (default=off).  */
  const char *st_rfu5_help; /**< @brief Allow RFU bit 5 help description.  */
  int st_rfu4_flag;	/**< @brief Allow RFU bit 4 (default=off).  */
  const char *st_rfu4_help; /**< @brief Allow RFU bit 4 help description.  */
  int st_rfu3_flag;	/**< @brief Allow RFU bit 3 (default=off).  */
  const char *st_rfu3_help; /**< @brief Allow RFU bit 3 help description.  */
  int st_rfu2_flag;	/**< @brief Allow RFU bit 2 (default=off).  */
  const char *st_rfu2_help; /**< @brief Allow RFU bit 2 help description.  */
  int gen_qualified_sig_flag;	/**< @brief Generate qualified electronic signature (default=off).  */
  const char *gen_qualified_sig_help; /**< @brief Generate qualified electronic signature help description.  */
  int gen_sig_flag;	/**< @brief Generate electronic signature (default=off).  */
  const char *gen_sig_help; /**< @brief Generate electronic signature help description.  */
  int read_eid_flag;	/**< @brief Read access to eID application (Deprecated) (default=off).  */
  const char *read_eid_help; /**< @brief Read access to eID application (Deprecated) help description.  */
  int is_rfu4_flag;	/**< @brief Allow RFU bit 4 (default=off).  */
  const char *is_rfu4_help; /**< @brief Allow RFU bit 4 help description.  */
  int is_rfu3_flag;	/**< @brief Allow RFU bit 3 (default=off).  */
  const char *is_rfu3_help; /**< @brief Allow RFU bit 3 help description.  */
  int is_rfu2_flag;	/**< @brief Allow RFU bit 2 (default=off).  */
  const char *is_rfu2_help; /**< @brief Allow RFU bit 2 help description.  */
  int read_iris_flag;	/**< @brief Read access to ePassport application: DG 4 (Iris) (default=off).  */
  const char *read_iris_help; /**< @brief Read access to ePassport application: DG 4 (Iris) help description.  */
  int read_finger_flag;	/**< @brief Read access to ePassport application: DG 3 (Fingerprint) (default=off).  */
  const char *read_finger_help; /**< @brief Read access to ePassport application: DG 3 (Fingerprint) help description.  */
  
  unsigned int help_given ;	/**< @brief Whether help was given.  */
  unsigned int version_given ;	/**< @brief Whether version was given.  */
  unsigned int out_cert_given ;	/**< @brief Whether out-cert was given.  */
  unsigned int role_given ;	/**< @brief Whether role was given.  */
  unsigned int type_given ;	/**< @brief Whether type was given.  */
  unsigned int issued_given ;	/**< @brief Whether issued was given.  */
  unsigned int expires_given ;	/**< @brief Whether expires was given.  */
  unsigned int sign_with_given ;	/**< @brief Whether sign-with was given.  */
  unsigned int scheme_given ;	/**< @brief Whether scheme was given.  */
  unsigned int csr_given ;	/**< @brief Whether csr was given.  */
  unsigned int chr_given ;	/**< @brief Whether chr was given.  */
  unsigned int sign_as_given ;	/**< @brief Whether sign-as was given.  */
  unsigned int key_given ;	/**< @brief Whether key was given.  */
  unsigned int out_key_given ;	/**< @brief Whether out-key was given.  */
  unsigned int out_desc_given ;	/**< @brief Whether out-desc was given.  */
  unsigned int cert_desc_given ;	/**< @brief Whether cert-desc was given.  */
  unsigned int issuer_name_given ;	/**< @brief Whether issuer-name was given.  */
  unsigned int issuer_url_given ;	/**< @brief Whether issuer-url was given.  */
  unsigned int subject_name_given ;	/**< @brief Whether subject-name was given.  */
  unsigned int subject_url_given ;	/**< @brief Whether subject-url was given.  */
  unsigned int write_dg17_given ;	/**< @brief Whether write-dg17 was given.  */
  unsigned int write_dg18_given ;	/**< @brief Whether write-dg18 was given.  */
  unsigned int write_dg19_given ;	/**< @brief Whether write-dg19 was given.  */
  unsigned int write_dg20_given ;	/**< @brief Whether write-dg20 was given.  */
  unsigned int write_dg21_given ;	/**< @brief Whether write-dg21 was given.  */
  unsigned int at_rfu32_given ;	/**< @brief Whether at-rfu32 was given.  */
  unsigned int at_rfu31_given ;	/**< @brief Whether at-rfu31 was given.  */
  unsigned int at_rfu30_given ;	/**< @brief Whether at-rfu30 was given.  */
  unsigned int at_rfu29_given ;	/**< @brief Whether at-rfu29 was given.  */
  unsigned int read_dg1_given ;	/**< @brief Whether read-dg1 was given.  */
  unsigned int read_dg2_given ;	/**< @brief Whether read-dg2 was given.  */
  unsigned int read_dg3_given ;	/**< @brief Whether read-dg3 was given.  */
  unsigned int read_dg4_given ;	/**< @brief Whether read-dg4 was given.  */
  unsigned int read_dg5_given ;	/**< @brief Whether read-dg5 was given.  */
  unsigned int read_dg6_given ;	/**< @brief Whether read-dg6 was given.  */
  unsigned int read_dg7_given ;	/**< @brief Whether read-dg7 was given.  */
  unsigned int read_dg8_given ;	/**< @brief Whether read-dg8 was given.  */
  unsigned int read_dg9_given ;	/**< @brief Whether read-dg9 was given.  */
  unsigned int read_dg10_given ;	/**< @brief Whether read-dg10 was given.  */
  unsigned int read_dg11_given ;	/**< @brief Whether read-dg11 was given.  */
  unsigned int read_dg12_given ;	/**< @brief Whether read-dg12 was given.  */
  unsigned int read_dg13_given ;	/**< @brief Whether read-dg13 was given.  */
  unsigned int read_dg14_given ;	/**< @brief Whether read-dg14 was given.  */
  unsigned int read_dg15_given ;	/**< @brief Whether read-dg15 was given.  */
  unsigned int read_dg16_given ;	/**< @brief Whether read-dg16 was given.  */
  unsigned int read_dg17_given ;	/**< @brief Whether read-dg17 was given.  */
  unsigned int read_dg18_given ;	/**< @brief Whether read-dg18 was given.  */
  unsigned int read_dg19_given ;	/**< @brief Whether read-dg19 was given.  */
  unsigned int read_dg20_given ;	/**< @brief Whether read-dg20 was given.  */
  unsigned int read_dg21_given ;	/**< @brief Whether read-dg21 was given.  */
  unsigned int install_qual_cert_given ;	/**< @brief Whether install-qual-cert was given.  */
  unsigned int install_cert_given ;	/**< @brief Whether install-cert was given.  */
  unsigned int pin_management_given ;	/**< @brief Whether pin-management was given.  */
  unsigned int can_allowed_given ;	/**< @brief Whether can-allowed was given.  */
  unsigned int privileged_given ;	/**< @brief Whether privileged was given.  */
  unsigned int rid_given ;	/**< @brief Whether rid was given.  */
  unsigned int verify_community_given ;	/**< @brief Whether verify-community was given.  */
  unsigned int verify_age_given ;	/**< @brief Whether verify-age was given.  */
  unsigned int st_rfu5_given ;	/**< @brief Whether st-rfu5 was given.  */
  unsigned int st_rfu4_given ;	/**< @brief Whether st-rfu4 was given.  */
  unsigned int st_rfu3_given ;	/**< @brief Whether st-rfu3 was given.  */
  unsigned int st_rfu2_given ;	/**< @brief Whether st-rfu2 was given.  */
  unsigned int gen_qualified_sig_given ;	/**< @brief Whether gen-qualified-sig was given.  */
  unsigned int gen_sig_given ;	/**< @brief Whether gen-sig was given.  */
  unsigned int read_eid_given ;	/**< @brief Whether read-eid was given.  */
  unsigned int is_rfu4_given ;	/**< @brief Whether is-rfu4 was given.  */
  unsigned int is_rfu3_given ;	/**< @brief Whether is-rfu3 was given.  */
  unsigned int is_rfu2_given ;	/**< @brief Whether is-rfu2 was given.  */
  unsigned int read_iris_given ;	/**< @brief Whether read-iris was given.  */
  unsigned int read_finger_given ;	/**< @brief Whether read-finger was given.  */

  int csr_mode_counter; /**< @brief Counter for mode csr */
  int manual_mode_counter; /**< @brief Counter for mode manual */
} ;

/** @brief The additional parameters to pass to parser functions */
struct cmdline_parser_params
{
  int override; /**< @brief whether to override possibly already present options (default 0) */
  int initialize; /**< @brief whether to initialize the option structure gengetopt_args_info (default 1) */
  int check_required; /**< @brief whether to check that all required options were provided (default 1) */
  int check_ambiguity; /**< @brief whether to check for options already specified in the option structure gengetopt_args_info (default 0) */
  int print_errors; /**< @brief whether getopt_long should print an error message for a bad option (default 1) */
} ;

/** @brief the purpose string of the program */
extern const char *gengetopt_args_info_purpose;
/** @brief the usage string of the program */
extern const char *gengetopt_args_info_usage;
/** @brief the description string of the program */
extern const char *gengetopt_args_info_description;
/** @brief all the lines making the help output */
extern const char *gengetopt_args_info_help[];

/**
 * The command line parser
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser (int argc, char **argv,
  struct gengetopt_args_info *args_info);

/**
 * The command line parser (version with additional parameters - deprecated)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param override whether to override possibly already present options
 * @param initialize whether to initialize the option structure my_args_info
 * @param check_required whether to check that all required options were provided
 * @return 0 if everything went fine, NON 0 if an error took place
 * @deprecated use cmdline_parser_ext() instead
 */
int cmdline_parser2 (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  int override, int initialize, int check_required);

/**
 * The command line parser (version with additional parameters)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param params additional parameters for the parser
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_ext (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  struct cmdline_parser_params *params);

/**
 * Save the contents of the option struct into an already open FILE stream.
 * @param outfile the stream where to dump options
 * @param args_info the option struct to dump
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_dump(FILE *outfile,
  struct gengetopt_args_info *args_info);

/**
 * Save the contents of the option struct into a (text) file.
 * This file can be read by the config file parser (if generated by gengetopt)
 * @param filename the file where to save
 * @param args_info the option struct to save
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_file_save(const char *filename,
  struct gengetopt_args_info *args_info);

/**
 * Print the help
 */
void cmdline_parser_print_help(void);
/**
 * Print the version
 */
void cmdline_parser_print_version(void);

/**
 * Initializes all the fields a cmdline_parser_params structure 
 * to their default values
 * @param params the structure to initialize
 */
void cmdline_parser_params_init(struct cmdline_parser_params *params);

/**
 * Allocates dynamically a cmdline_parser_params structure and initializes
 * all its fields to their default values
 * @return the created and initialized cmdline_parser_params structure
 */
struct cmdline_parser_params *cmdline_parser_params_create(void);

/**
 * Initializes the passed gengetopt_args_info structure's fields
 * (also set default values for options that have a default)
 * @param args_info the structure to initialize
 */
void cmdline_parser_init (struct gengetopt_args_info *args_info);
/**
 * Deallocates the string fields of the gengetopt_args_info structure
 * (but does not deallocate the structure itself)
 * @param args_info the structure to deallocate
 */
void cmdline_parser_free (struct gengetopt_args_info *args_info);

/**
 * Checks that all the required options were specified
 * @param args_info the structure to check
 * @param prog_name the name of the program that will be used to print
 *   possible errors
 * @return
 */
int cmdline_parser_required (struct gengetopt_args_info *args_info,
  const char *prog_name);

extern const char *cmdline_parser_role_values[];  /**< @brief Possible values for role. */
extern const char *cmdline_parser_type_values[];  /**< @brief Possible values for type. */
extern const char *cmdline_parser_scheme_values[];  /**< @brief Possible values for scheme. */


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* CVC_CREATE_CMDLINE_H */
