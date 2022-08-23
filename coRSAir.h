/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   coRSAir.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vduchi <vduchi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/08/08 16:55:47 by vduchi            #+#    #+#             */
/*   Updated: 2022/08/08 22:00:58 by vduchi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef CORSAIR_H
# define CORSAIR_H

# include <math.h>
# include <stdio.h>
# include <fcntl.h>
# include <stdlib.h>
# include <unistd.h>
# include <string.h>
# include <openssl/rsa.h>
# include <openssl/evp.h>
# include <openssl/ssl.h>
# include <openssl/pem.h>
# include <openssl/bn.h>

// All the utils functions
int	ft_strlen(unsigned char *str);
char	*ft_get_name(const char *from);
void	*ft_print_values(RSA *rsa1, RSA *rsa2);
RSA	*ft_create_key(BIGNUM *p, BIGNUM *mod, BIGNUM *e);

// All the free functions
int	ft_free_all_corsair(BIGNUM *p1, BIGNUM *p2, BN_CTX *ctx, EVP_PKEY *evp1, EVP_PKEY *evp2, RSA *rsa1, \
		RSA *rsa2, RSA *rdec1, RSA *rdec2);
int	ft_free_small_creator(BIGNUM *p1, BIGNUM *p2, BIGNUM *q1, BIGNUM *q2, BIGNUM *n1, BIGNUM *n2, \
		BN_CTX *bnctx1, BN_CTX *bnctx2);
void	ft_free_rsa_creator(RSA *rsa1, RSA *rsa2, BN_CTX *ctx1, BN_CTX *ctx2, BIGNUM *phi1, BIGNUM *phi2, BIGNUM *p11, \
			BIGNUM *q11, BIGNUM *q21);
void	ft_free_rsa_corsair(BN_CTX *ctx, BIGNUM *p1, BIGNUM *q1, BIGNUM *phi, BIGNUM *n, BIGNUM *d, \
			BIGNUM *q, BIGNUM *exp, BIGNUM *dmp, BIGNUM *dmq, BIGNUM *iqmp, RSA *rsa);
void	ft_free_bn_creator(BIGNUM *d1, BIGNUM *d2, BIGNUM *p11, BIGNUM *q11, BIGNUM *q21, BIGNUM *exp1, BIGNUM *exp2, \
			BIGNUM *phi1, BIGNUM *phi2, BIGNUM *dmp1, BIGNUM *dmp2, BIGNUM *dmq1, BIGNUM *dmq2, BIGNUM *iqmp1, \
			BIGNUM *iqmp2, RSA *rsa1, RSA *rsa2, BN_CTX *ctx1, BN_CTX *ctx2);
#endif
