/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   free_funcs.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vduchi <vduchi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/08/05 08:57:10 by vduchi            #+#    #+#             */
/*   Updated: 2022/08/08 16:49:13 by vduchi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "coRSAir.h"

int	ft_free_all_corsair(BIGNUM *p1, BIGNUM *p2, BN_CTX *ctx, EVP_PKEY *evp1, EVP_PKEY *evp2, \
		RSA *rsa1, RSA *rsa2, RSA *rdec1, RSA *rdec2)
{
	if (p1 && !rdec1)
		BN_free(p1);
	if (p2 && !rdec2)
		BN_free(p2);
	if (ctx)
		BN_CTX_free(ctx);
	if (evp1)
		EVP_PKEY_free(evp1);
	if (evp2)
		EVP_PKEY_free(evp2);
	if (rsa1)
		RSA_free(rsa1);
	if (rsa2)
		RSA_free(rsa2);
	if (rdec1)
		RSA_free(rdec1);
	if (rdec2)
		RSA_free(rdec2);
	return (0);
}

int	ft_free_small_creator(BIGNUM *p1, BIGNUM *p2, BIGNUM *q1, BIGNUM *q2, BIGNUM *n1, BIGNUM *n2, \
		BN_CTX *bnctx1, BN_CTX *bnctx2)
{
	if (p1)
		BN_free(p1);
	if (p2)
		BN_free(p2);
	if (q1)
		BN_free(q1);
	if (q2)
		BN_free(q2);
	if (n1)
		BN_free(n1);
	if (n2)
		BN_free(n2);
	if (bnctx1)
		BN_CTX_free(bnctx1);
	if (bnctx2)
		BN_CTX_free(bnctx2);
	return (0);
}


void	ft_free_rsa_creator(RSA *rsa1, RSA *rsa2, BN_CTX *ctx1, BN_CTX *ctx2, BIGNUM *phi1, BIGNUM *phi2, BIGNUM *p11, \
			BIGNUM *q11, BIGNUM *q21)
{
	if (rsa1)
		RSA_free(rsa1);
	if (rsa2)
		RSA_free(rsa2);
	if (ctx1)
		BN_CTX_free(ctx1);	
	if (ctx2)
		BN_CTX_free(ctx2);
	if (phi1)
		BN_free(phi1);
	if (phi2)
		BN_free(phi2);
	if (p11)
		BN_free(p11);
	if (q11)
		BN_free(q11);
	if (q21)
		BN_free(q21);
}

void	ft_free_rsa_corsair(BN_CTX *ctx, BIGNUM *p1, BIGNUM *q1, BIGNUM *phi, BIGNUM *n, BIGNUM *d, \
			BIGNUM *q, BIGNUM *exp, BIGNUM *dmp, BIGNUM *dmq, BIGNUM *iqmp, RSA *rsa)
{
	if (ctx)
		BN_CTX_free(ctx);
	if (p1)
		BN_free(p1);
	if (q1)
		BN_free(q1);
	if (phi)
		BN_free(phi);
	if (n)
		BN_free(n);
	if (d)
		BN_free(d);
	if (q)
		BN_free(q);
	if (exp)
		BN_free(exp);
	if (dmp)
		BN_free(dmp);
	if (dmq)
		BN_free(dmq);
	if (iqmp)
		BN_free(iqmp);
	if (rsa)
		RSA_free(rsa);
}

void	ft_free_bn_creator(BIGNUM *d1, BIGNUM *d2, BIGNUM *p11, BIGNUM *q11, BIGNUM *q21, BIGNUM *exp1, BIGNUM *exp2, \
			BIGNUM *phi1, BIGNUM *phi2, BIGNUM *dmp1, BIGNUM *dmp2, BIGNUM *dmq1, BIGNUM *dmq2, BIGNUM *iqmp1, \
			BIGNUM *iqmp2, RSA *rsa1, RSA *rsa2, BN_CTX *ctx1, BN_CTX *ctx2)
{
	if (rsa1)
		RSA_free(rsa1);
	if (rsa2)
		RSA_free(rsa2);
	if (ctx1)
		BN_CTX_free(ctx1);
	if (ctx2)
		BN_CTX_free(ctx2);
	if (phi1)
		BN_free(phi1);
	if (phi2)
		BN_free(phi2);
	if (p11)
		BN_free(p11);
	if (q11)
		BN_free(q11);
	if (q21)
		BN_free(q21);
	if (d1)
		BN_free(d1);
	if (d2)
		BN_free(d2);
	if (exp1)
		BN_free(exp1);
	if (exp2)
		BN_free(exp2);
	if (dmp1)
		BN_free(dmp1);
	if (dmp2)
		BN_free(dmp2);
	if (dmq1)
		BN_free(dmq1);
	if (dmq2)
		BN_free(dmq2);
	if (iqmp1)
		BN_free(iqmp1);
	if (iqmp2)
		BN_free(iqmp2);
}
