/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   take_keys.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vduchi <vduchi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/08/08 16:20:42 by vduchi            #+#    #+#             */
/*   Updated: 2022/08/08 22:13:10 by vduchi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "coRSAir.h"

int	main(int argc, char *argv[])
{
	int			len;
	char			*pub1;
	char			*pub2;
	const char		*cert1;
	const char		*cert2;

	EVP_PKEY		*evp1;
	EVP_PKEY		*evp2;
	RSA			*rsa1;
	RSA			*rsa2;
	RSA			*rdec1;
	RSA			*rdec2;

	FILE			*pub_key1;
	FILE			*pub_key2;
	FILE			*first_key;
	FILE			*second_key;

	BIGNUM			*p1;
	BIGNUM			*p2;
	BIGNUM			*e1;
	BIGNUM			*e2;
	BIGNUM			*mod1;
	BIGNUM			*mod2;

	BN_CTX			*ctx;
	
	if (argc != 3)
	{
		printf("Please insert all the elements needed in this order:\n\
	1. Executable file\n\
	2. First certificate\n\
	3. Second certificate\n");
		return (0);
	}

	cert1 = argv[1];
	cert2 = argv[2];
	pub1 = ft_get_name(cert1);
	pub2 = ft_get_name(cert2);
	first_key = fopen(cert1, "r");
	second_key = fopen(cert2, "r");
	pub_key1 = fopen(pub1, "w+");
	pub_key2 = fopen(pub2, "w+");
	
	printf("Looking for the public keys...\n");
	if (!first_key || !second_key)
	{
		printf("Error: one or more files not found!\n");
		if (first_key)
			fclose(first_key);
		if (second_key)
			fclose(second_key);
		return (0);
	}

	p1 = BN_new();
	p2 = BN_new();
	ctx = BN_CTX_new();
	evp1 = EVP_PKEY_new();
	evp2 = EVP_PKEY_new();
	if (!p1 || !p2 || !ctx)
	{
		printf("Error: failed generating P or CTX!\n");
		return (ft_free_all_corsair(p1, p2, ctx, NULL, NULL, NULL, NULL, NULL, NULL));
	}

	PEM_read_PUBKEY(first_key, &evp1, NULL, NULL);
	PEM_read_PUBKEY(second_key, &evp2, NULL, NULL);
	if (!evp1 || !evp2)
	{
		printf("Error: failed reading the certificates!\n");
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp1, NULL, NULL, NULL, NULL));
	}
	else
		printf("Key founded correctly!\n");
	
	rsa1 = EVP_PKEY_get0_RSA(evp1);
	rsa2 = EVP_PKEY_get0_RSA(evp2);
	if (!rsa1 || !rsa2)
	{
		printf("Error: failed taking the public keys!\n");
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp1, rsa1, rsa2, NULL, NULL));
	}

	RSA_get0_key(rsa1, &mod1, &e1, NULL);
	RSA_get0_key(rsa2, &mod2, &e2, NULL);
	if (!BN_gcd(p1, mod1, mod2, ctx) || !BN_copy(p2, p1))
	{
		printf("Error: gcd not found or copy failed!\n");
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, NULL, NULL));
	}
	fclose(first_key);
	fclose(second_key);

	printf("Creating the private keys...\n");
	rdec1 = ft_create_key(p1, mod1, e1);
	rdec2 = ft_create_key(p2, mod2, e2);
	if (!rdec1 || !rdec2)
	{
		printf("Error: failed creating the private key!\n");
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, rdec1, rdec2));
	}
	printf("Private keys created successfully!\n");

	if (PEM_write_RSAPrivateKey(pub_key1, rdec1, NULL, NULL, NULL, NULL, NULL) != 1
		|| PEM_write_RSAPrivateKey(pub_key2, rdec2, NULL, NULL, NULL, NULL, NULL) != 1)
	{
		printf("Error: failed writing the private keys to the relative files!\n");
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, rdec1, rdec2));
	}

	ft_print_values(rsa1, rsa2);
	printf("Keys written in the files: %s and %s\n", pub1, pub2);

	printf("Process completed\n");

	free(pub1);
	free(pub2);
	fclose(pub_key1);
	fclose(pub_key2);

	EVP_PKEY_free(evp1);	
	EVP_PKEY_free(evp2);
	BN_CTX_free(ctx);
	RSA_free(rdec1);
	RSA_free(rdec2);

	return (0);
}
