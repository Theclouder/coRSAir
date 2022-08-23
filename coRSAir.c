/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   coRSAir.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vduchi <vduchi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/07/16 06:09:36 by vduchi            #+#    #+#             */
/*   Updated: 2022/08/08 22:14:23 by vduchi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "coRSAir.h"

int	ft_decrypt(RSA *rsa, char *from)
{
	int				len;
	unsigned char	*res;

	res = (unsigned char *)malloc(RSA_size(rsa));
	res[0] = '\0';
	len = RSA_private_decrypt(RSA_size(rsa), from, res, rsa, RSA_PKCS1_PADDING);
	if (len <= 0)
	{
		free(res);
		return (0);
	}
	res[len] = '\0';
	printf("Message decrypted: %s\n", res);
	free(res);
	return (1);
}

char	*recollect_message(int fd)
{
	int		len;
	char	*str;

	str = (char *)malloc(sizeof(char) * 1001);
	if (!str)
		return (NULL);
	len = read(fd, str, 1000);
	str[len] = '\0';
	return (str);
}

int	main(int argc, char **argv)
{
	int			res;
	int			first_file;
	int			second_file;
	unsigned char		*str1;
	unsigned char		*str2;
	const char		*cert1;
	const char		*cert2;
	const char		*mess1;
	const char		*mess2;

	EVP_PKEY		*evp1;
	EVP_PKEY		*evp2;
	RSA			*rsa1;
	RSA			*rsa2;
	RSA			*rdec1;
	RSA			*rdec2;

	FILE			*first_key;
	FILE			*second_key;

	BIGNUM			*p1;
	BIGNUM			*p2;
	BIGNUM			*e1;
	BIGNUM			*e2;
	BIGNUM			*mod1;
	BIGNUM			*mod2;

	BN_CTX			*ctx;
	
	if (argc != 5)
	{
		printf("Please insert all the elements needed in this order:\n\
	1. Executable file\n\
	2. First certificate\n\
	3. Second certificate\n\
	4. First file name with the encrypted message\n\
	5. Second file name with the encrypted message\n");
		return (0);
	}
	
	cert1 = argv[1];
	cert2 = argv[2];
	mess1 = argv[3];
	mess2 = argv[4];

	first_key = fopen(cert1, "r");
	second_key = fopen(cert2, "r");
	first_file = open(mess1, O_RDONLY);
	second_file = open(mess2, O_RDONLY);
	
	printf("Looking for the public keys...\n");
	if (!first_key || !second_key || first_file <= 0|| second_file <= 0)
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
	if (!p1 || !p2 || !ctx)
	{
		printf("Error: failed generating P or CTX!\n");
		return (ft_free_all_corsair(p1, p2, ctx, NULL, NULL, NULL, NULL, NULL, NULL));
	}

	PEM_read_PUBKEY(first_key, &evp1, NULL, NULL);
	PEM_read_PUBKEY(second_key, &evp2, NULL, NULL);
	if (!evp1 || !evp2)
	{
		printf("Error: failed reading the certificates and taking the public key!\n");
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, NULL, NULL, NULL, NULL));
	}
	else
		printf("Key founded correctly!\n");
	
	rsa1 = EVP_PKEY_get0_RSA(evp1);
	rsa2 = EVP_PKEY_get0_RSA(evp2);
	if (!rsa1 || !rsa2)
	{
		printf("Error: failed reading the certificates and taking the public key!\n");
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, NULL, NULL));
	}
	
	RSA_get0_key(rsa1, &mod1, &e1, NULL);
	RSA_get0_key(rsa2, &mod2, &e2, NULL);
	if (!BN_gcd(p1, mod1, mod2, ctx) || !BN_copy(p2, p1))
	{
		printf("Error: gcd not found or copy failed!\n");
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, NULL, NULL));
	}

	printf("Creating the private keys...\n");
	rdec1 = ft_create_key(p1, mod1, e1);
	rdec2 = ft_create_key(p2, mod2, e2);
	if (!rdec1 || !rdec2)
	{
		printf("Error: failed creating the private key!\n");
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, rdec1, rdec2));
	}
	printf("Private key created successfully!\n");

	str1 = recollect_message(first_file);
	str2 = recollect_message(second_file);
	if (!str1 || !str2)
	{
		printf("Error: failed allocating memory!\n");
		if (str1)
			free(str1);
		if (str2)
			free(str2);
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, rdec1, rdec2));
	}
	fclose(first_key);
	fclose(second_key);
	close(first_file);
	close(second_file);
	
	if (RSA_check_key(rdec1) != 1 || RSA_check_key(rdec2) != 1)
	{
		printf("Error generating the key!\n");
		if (str1)
			free(str1);
		if (str2)
			free(str2);
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, rdec1, rdec2));
	}

	printf("Decrypting the messages...\n");
	res = ft_decrypt(rdec1, str1);
	if (res == 0)
	{
		printf("Error decrypting the message!\n");
		if (str1)
			free(str1);
		if (str2)
			free(str2);
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, rdec1, rdec2));
	}

	res = ft_decrypt(rdec2, str2);
	if (res == 0)
	{
		printf("Error decrypting the message!\n");
		if (str1)
			free(str1);
		if (str2)
			free(str2);
		return (ft_free_all_corsair(p1, p2, ctx, evp1, evp2, rsa1, rsa2, rdec1, rdec2));
	}

	printf("Process completed\n");
	free(str1);
	free(str2);

	BN_CTX_free(ctx);
	RSA_free(rdec1);
	RSA_free(rdec2);
	RSA_free(rsa1);
	RSA_free(rsa2);

	return (0);
}
