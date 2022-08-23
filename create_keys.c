/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   create_keys.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vduchi <vduchi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/07/16 06:09:36 by vduchi            #+#    #+#             */
/*   Updated: 2022/08/08 18:33:53 by vduchi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "coRSAir.h"

int	ft_encrypt_message(RSA *rsa, const unsigned char *message, unsigned char *encr_mes, const char *file)
{
	FILE			*arc;
	unsigned int	len;

	if (RSA_check_key(rsa) != 1)
	{
		printf("Key not created successfully!\n");
		return (0);
	}

	len = RSA_public_encrypt(ft_strlen(message), message, encr_mes, rsa, RSA_PKCS1_PADDING);

	arc = fopen(file, "w+");
	fwrite(encr_mes, 1, len, arc);
	fclose(arc);
	return (len);
}

int	ft_generate_key(BIGNUM *n1, BIGNUM *n2, unsigned char *e, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1, BIGNUM *q2, \
			const char *cert1, const char *cert2, const char *mess1, const char *mess2)
{
	RSA		*rsa1;
	RSA		*rsa2;

	FILE		*bp1;
	FILE		*bp2;

	BIGNUM		*d1;
	BIGNUM		*d2;
	BIGNUM		*p11;
	BIGNUM		*q11;
	BIGNUM		*q21;
	BIGNUM		*phi1;
	BIGNUM		*phi2;
	BIGNUM		*exp1;
	BIGNUM		*exp2;
	BIGNUM		*dmp1;
	BIGNUM		*dmp2;
	BIGNUM		*dmq1;
	BIGNUM		*dmq2;
	BIGNUM		*iqmp1;
	BIGNUM		*iqmp2;
	
	BN_CTX		*ctx1;
	BN_CTX		*ctx2;

	unsigned char		*encr_mes1;
	unsigned char		*encr_mes2;
	const unsigned char	*message1 = "If you have found me, you did a good job!!";
	const unsigned char	*message2 = "And also good job for finding me!";

	printf("Creating the two public keys...\n");

	bp1 = fopen(cert1, "w+");
	bp2 = fopen(cert2, "w+");

	d1 = BN_new();
	d2 = BN_new();
	p11 = BN_new();
	q11 = BN_new();
	q21 = BN_new();
	exp1 = BN_new();
	exp2 = BN_new();
	phi1 = BN_new();
	phi2 = BN_new();
	dmp1 = BN_new();
	dmp2 = BN_new();
	dmq1 = BN_new();
	dmq2 = BN_new();
	iqmp1 = BN_new();
	iqmp2 = BN_new();

	rsa1 = RSA_new();
	rsa2 = RSA_new();
	ctx1 = BN_CTX_new();
	ctx2 = BN_CTX_new();

	if (!d1 || !d2 || !p11 || !q11 || !q21 || !exp1 || !exp2 || !phi1 || !phi2 || !dmp1
		|| !dmp2 || !dmq1 || !dmq2 || !iqmp1 || !iqmp2 || !rsa1 || !rsa2 || !ctx1 || !ctx2)
	{
		printf("Error: failed generating the BIGNUM!\n");
		ft_free_bn_creator(d1, d2, p11, q11, q21, exp1, exp2, phi1, phi2, dmp1, dmp2, \
			dmq1, dmq2, iqmp1, iqmp2, rsa1, rsa2, ctx1, ctx2);
		return (0);
	}

	if (!BN_dec2bn(&exp1, e) || !BN_dec2bn(&exp2, e) || !BN_sub(p11, p1, BN_value_one())
		|| !BN_sub(q11, q1, BN_value_one()) || !BN_sub(q21, q2, BN_value_one()) || !BN_mul(phi1, p11, q11, ctx1)
		|| !BN_mul(phi2, p11, q21, ctx2) || !BN_mod_inverse(d1, exp1, phi1, ctx1) || !BN_mod_inverse(d2, exp2, phi2, ctx2)
		|| !BN_mod(dmp1, d1, p11, ctx1) || !BN_mod(dmp2, d2, p11, ctx2) || !BN_mod(dmq1, d1, q11, ctx1)
		|| !BN_mod(dmq2, d2, q21, ctx2) || !BN_mod_inverse(iqmp1, q1, p1, ctx1) || !BN_mod_inverse(iqmp2, q2, p2, ctx2))
	{
		printf("Error: failed doing mathematical operations with the BIGNUM!\n");
		ft_free_bn_creator(d1, d2, p11, q11, q21, exp1, exp2, phi1, phi2, dmp1, dmp2, \
			dmq1, dmq2, iqmp1, iqmp2, rsa1, rsa2, ctx1, ctx2);
		return (0);
	}

	RSA_set0_key(rsa1, n1, exp1, d1);
	RSA_set0_factors(rsa1, p1, q1);
	RSA_set0_crt_params(rsa1, dmp1, dmq1, iqmp1);

	RSA_set0_key(rsa2, n2, exp2, d2);
	RSA_set0_factors(rsa2, p2, q2);
	RSA_set0_crt_params(rsa2, dmp2, dmq2, iqmp2);
	if (RSA_check_key(rsa1) != 1 || RSA_check_key(rsa2) != 1)
	{
		printf("Error: failed creating the RSA keys!\n");
		ft_free_rsa_creator(rsa1, rsa2, ctx1, ctx2, phi1, phi2, p11, q11, q21);
		return (0);
	}

	if (PEM_write_RSAPublicKey(bp1, rsa1) != 1 || PEM_write_RSAPublicKey(bp2, rsa2) != 1)
	{
		printf("Error: failed writing the certificates!\n");
		ft_free_rsa_creator(rsa1, rsa2, ctx1, ctx2, phi1, phi2, p11, q11, q21);
		return (0);
	}
	fclose(bp1);
	fclose(bp2);

	printf("Keys created and written successfully!\n");

	encr_mes1 = malloc(RSA_size(rsa1));
	encr_mes2 = malloc(RSA_size(rsa2));
	if (!encr_mes1 || !encr_mes2)
	{
		printf("Error: failed reserving memory for the messages!\n");
		if (encr_mes1)
			free(encr_mes1);
		if (encr_mes2)
			free(encr_mes2);
		ft_free_rsa_creator(rsa1, rsa2, ctx1, ctx2, phi1, phi2, p11, q11, q21);
		return (0);
	}
	encr_mes1[0] = '\0';
	encr_mes2[0] = '\0';
	printf("Encrypting the two messages...\n");
	if (ft_encrypt_message(rsa1, message1, encr_mes1, mess1) == 0 
		|| ft_encrypt_message(rsa2, message2, encr_mes2, mess2) == 0)
	{
		printf("Error encrypting the messages!\n");
		if (encr_mes1)
			free(encr_mes1);
		if (encr_mes2)
			free(encr_mes2);
		ft_free_rsa_creator(rsa1, rsa2, ctx1, ctx2, phi1, phi2, p11, q11, q21);
		return (0);
	}
	ft_free_rsa_creator(rsa1, rsa2, ctx1, ctx2, phi1, phi2, p11, q11, q21);
	free(encr_mes1);
	free(encr_mes2);
	printf("Messages encrypted successfully!\n");
	return (1);
}

int	main(int argc, char *argv[])
{
	RSA		*rsa1;
	RSA		*rsa2;
	
	BIGNUM		*p1;
	BIGNUM		*p2;
	BIGNUM		*q1;
	BIGNUM		*q2;
	BIGNUM		*n1;
	BIGNUM		*n2;
	BN_CTX		*bnctx1;
	BN_CTX		*bnctx2;

	const char			*cert1;
	const char			*cert2;
	const char			*mess1;
	const char			*mess2;
	unsigned char			*e;

	if (argc != 5)
	{
		printf("Please insert all the elements needed in this order:\n\
	1. Executable file\n\
	2. First certificate name\n\
	3. Second certificate name\n\
	4. First file name for the first message\n\
	5. Second file name for the second message\n");
		return (0);
	}

	cert1 = argv[1];
	cert2 = argv[2];
	mess1 = argv[3];
	mess2 = argv[4];

	e = "65537";
	p1 = BN_new();
	p2 = BN_new();
	q1 = BN_new();	
	q2 = BN_new();
	n1 = BN_new();
	n2 = BN_new();
	bnctx1 = BN_CTX_new();
	bnctx2 = BN_CTX_new();

	printf("Creating the BIGNUM for the public keys...\n");

	if (!p1 || !p2 || !q1 || !q2 || !n1 || !n2 || !bnctx1 || !bnctx2)
	{
		printf("Error: failed creating the basic parameters!\n");
		return (ft_free_small_creator(p1, p2, q1, q2, n1, n2, bnctx1, bnctx2));
	}
	if (BN_generate_prime_ex(p1, 2048, 0, NULL, NULL, NULL) == 0)
	{
		printf("Error: failed to generate the p number!\n");
		return (ft_free_small_creator(p1, p2, q1, q2, n1, n2, bnctx1, bnctx2));
	}
	if (BN_generate_prime_ex2(q1, 2048, 0, NULL, NULL, NULL, bnctx1) == 0)
	{
		printf("Error: failed to generate the first q number!\n");
		return (ft_free_small_creator(p1, p2, q1, q2, n1, n2, bnctx1, bnctx2));
	}
	if (BN_generate_prime_ex2(q2, 2048, 0, NULL, NULL, NULL, bnctx2) == 0)
	{
		printf("Error: failed to generate the second q number!\n");
		return (ft_free_small_creator(p1, p2, q1, q2, n1, n2, bnctx1, bnctx2));
	}
	if (!BN_copy(p2, p1))
	{
		printf("Error: failed to copy the p1 to p2!\n");
		return (ft_free_small_creator(p1, p2, q1, q2, n1, n2, bnctx1, bnctx2));
	}
	if (BN_mul(n1, p1, q1, bnctx1) <= 0 || BN_mul(n2, p2, q2, bnctx2) <= 0)
	{
		printf("Error: failed to handle the multiplication!\n");
		return (ft_free_small_creator(p1, p2, q1, q2, n1, n2, bnctx1, bnctx2));
	}
	printf("Numbers generated successfully!\n");
	if (!ft_generate_key(n1, n2, e, p1, p2, q1, q2, cert1, cert2, mess1, mess2))
	{
		return (ft_free_small_creator(NULL, NULL, NULL, NULL, NULL, NULL, bnctx1, bnctx2));
	}

	printf("Process completed!\n");
	BN_CTX_free(bnctx1);
	BN_CTX_free(bnctx2);

	return (0);
}
