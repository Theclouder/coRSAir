/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vduchi <vduchi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/08/08 16:55:06 by vduchi            #+#    #+#             */
/*   Updated: 2022/08/08 22:02:21 by vduchi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "coRSAir.h"

int	ft_strlen(unsigned char *str)
{
	int	i;

	i = 0;
	while (str[i] != '\0')
		i++;
	return (i);
}

void	*ft_print_values(RSA *rsa1, RSA *rsa2)
{
	char	*mod1;
	char	*mod2;
	char	*exp1;
	char	*exp2;

	mod1 = BN_bn2dec(RSA_get0_n(rsa1));
	mod2 = BN_bn2dec(RSA_get0_n(rsa2));
	exp1 = BN_bn2dec(RSA_get0_e(rsa1));
	exp2 = BN_bn2dec(RSA_get0_e(rsa2));
	printf("First key:\nModulus: %s\nExponent: %s\nSecond key:\nModulus: %s\nExponent: %s\n", mod1, exp1, mod2, exp2);
	
	free(mod1);
	free(mod2);
	free(exp1);
	free(exp2);
}
char	*ft_get_name(const char *from)
{
	int	i;
	int	len;
	char	*to;
	char	*then = "private";
	char	*before = "my_";

	i = 0;
	len = 0;
	while (from[len] != '.')
		len++;
	to = (char *)malloc(sizeof(char) * (len + 11));
	while (i < (len + 11))
	{
		if (i < 3)
			to[i] = before[i];
		else if (i >= 3 && i < (len + 3))
			to[i] = from[i - 3];
		else if (i == (len + 3))
			to[i] = '.';
		else
			to[i] = then[i - (len + 4)];
		i++;
	}
	to[i] = '\0';
	return (to);
}

RSA	*ft_create_key(BIGNUM *p, BIGNUM *mod, BIGNUM *e)
{
	RSA 		*rsa;

	BIGNUM		*n;
	BIGNUM		*p1;
	BIGNUM		*d;
	BIGNUM		*q;
	BIGNUM		*q1;
	BIGNUM		*exp;
	BIGNUM		*phi;
	BIGNUM		*dmp;
	BIGNUM		*dmq;
	BIGNUM		*iqmp;

	BN_CTX		*ctx;

	n = BN_new();
	p1 = BN_new();
	d = BN_new();
	q = BN_new();
	q1 = BN_new();
	exp = BN_new();
	phi = BN_new();
	dmp = BN_new();
	dmq = BN_new();
	iqmp = BN_new();

	rsa = RSA_new();
	ctx = BN_CTX_new();

	if (!BN_copy(n, mod) || !BN_copy(exp, e) ||	!BN_div(q, NULL, n, p, ctx) || !BN_sub(p1, p, BN_value_one())
		|| !BN_sub(q1, q, BN_value_one()) || !BN_mul(phi, p1, q1, ctx) || !BN_mod_inverse(d, exp, phi, ctx)
		|| !BN_mod(dmp, d, p1, ctx) || !BN_mod(dmq, d, q1, ctx) || !BN_mod_inverse(iqmp, q, p, ctx))
	{
		ft_free_rsa_corsair(ctx, p1, q1, phi, n, d, q, exp, dmp, dmq, iqmp, rsa);
		return (NULL);
	}

	RSA_set0_key(rsa, n, exp, d);
	RSA_set0_factors(rsa, p, q);
	RSA_set0_crt_params(rsa, dmp, dmq, iqmp);
	if (RSA_check_key(rsa) != 1)
	{
		ft_free_rsa_corsair(ctx, p1, q1, phi, n, d, q, exp, dmp, dmq, iqmp, rsa);
		return (NULL);
	}

	BN_CTX_free(ctx);
	BN_free(p1);
	BN_free(q1);
	BN_free(phi);
	return (rsa);
}
