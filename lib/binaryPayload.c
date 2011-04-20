/*
 * anontool Copyright Notice, License & Disclaimer
 *
 * Copyright 2006 by Antonatos Spiros, Koukis Demetres & Foukarakis Michael
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both the
 * copyright notice and this permission notice and warranty disclaimer appear
 * in supporting documentation, and that the names of the authors not be used
 * in advertising or publicity pertaining to distribution of the software without
 * specific, written prior permission.
 *
 * The authors disclaim all warranties with regard to this software, including all
 * implied warranties of merchantability and fitness.  In no event shall we be liable
 * for any special, indirect or consequential damages or any damages whatsoever
 * resulting from loss of use, data or profits, whether in an action of contract,
 * negligence or other tortious action, arising out of or in connection with the
 * use or performance of this software.
 */
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

#include "anonymization.h"

/*
 * Regular expressions (or lists of) with the decoders'/shellcodes' PCREs.
 */
pcre           *regexpIPAddress;
pcre           *regexpURL;
pcre           *regexpGenericWget;
pcre           *stuttgartPattern;
pcre           *wuerzburgPattern;
pcre           *konstanzPattern;
flist_t        *regexpGenericXOR;

/*
 *      Generic XOR decoders
 */
int binaryGenericXORInit()
{
        const char     *pcreError;
        int32_t         pcreErrorPos;
        uint32_t        i = 0;
        XORPcreHelper   test[17] = {
                {
                 "(.*)(\\xEB\\x02\\xEB\\x05\\xE8\\xF9\\xFF\\xFF\\xFF\\x5B\\x31\\xC9\\x66\\xB9(.)\\xFF\\x80\\x73\\x0E(.)\\x43\\xE2\\xF9)(.*)$",
                 "rbot 64k",
                 XF_NONE},
                {
                 "(.*)(\\xEB\\x02\\xEB\\x05\\xE8\\xF9\\xFF\\xFF\\xFF\\x5B\\x31\\xC9\\xB1(.)\\x80\\x73\\x0C(.)\\x43\\xE2\\xF9)(.*)$",
                 "rbot 265 byte",
                 XF_NONE},
                {
                 "(.*)(\\xEB\\x10\\x5A\\x4A\\x33\\xC9\\x66\\xB9(..)\\x80\\x34\\x0A(.)\\xE2\\xFA\\xEB\\x05\\xE8\\xEB\\xFF\\xFF\\xFF)(.*)$",
                 "bielefeld",
                 XF_NONE},
                {
                 "(.*)(\\xEB\\x02\\xEB\\x05\\xE8\\xF9\\xFF\\xFF\\xFF\\x5B\\x31\\xC9\\x66\\xB9(..)\\x80\\x73\\x0E(.)\\x43\\xE2\\xF9)(.*)$",
                 "halle",
                 XF_NONE},
                {
                 "(.*)(\\xEB\\x19\\x5E\\x31\\xC9\\x81\\xE9(....)\\x81\\x36(....)\\x81\\xEE\\xFC\\xFF\\xFF\\xFF\\xE2\\xF2\\xEB\\x05\\xE8\\xE2\\xFF\\xFF\\xFF)(.*)$",
                 "adenau xor",
                 XF_SIZE_INVERT},

                {
                 "(.*)(\\xEB\\x03\\x5D\\xEB\\x05\\xE8\\xF8\\xFF\\xFF\\xFF\\x8B\\xC5\\x83\\xC0\\x11\\x33\\xC9\\x66\\xB9(..)\\x80\\x30(.)\\x40\\xE2\\xFA)(.*)$",
                 "kaltenborn xor",
                 XF_NONE},
                {
                 "(.*)(\\xEB\\x10\\x5A\\x4A\\x31\\xC9\\x66\\xB9\(..)\\x80\\x34\\x0A(.)\\xE2\\xFA\\xEB\\x05\\xE8\\xEB\\xFF\\xFF\\xFF)(.*)$",
                 "deggendorf xor",
                 XF_NONE},
                {
                 "(.*)(\\xEB\\x0F\\x5B\\x33\\xC9\\x66\\xB9(..)\\x80\\x33(.)\\x43\\xE2\\xFA\\xEB\\x05\\xE8\\xEC\\xFF\\xFF\\xFF)(.*)$",
                 "langenfeld xor",
                 XF_NONE},
                {
                 "(.*)(\\xEB\\x03\\x5D\\xEB\\x05\\xE8\\xF8\\xFF\\xFF\\xFF\\x83\\xC5\\x15\\x90\\x90\\x90\\x8B\\xC5\\x33\\xC9\\x66\\xB9(..)\\x50\\x80\\x30(.)\\x40\\xE2\\xFA)(.*)$",
                 "saalfeld xor",
                 XF_NONE},
                {
                 "(.*)(\\x31\\xC9\\x83\\xE9(.)\\xD9\\xEE\\xD9\\x74\\x24\\xF4\\x5B\\x81\\x73\\x13(....)\\x83\\xEB\\xFC\\xE2\\xF4)(.*)$",
                 "schoenberg xor",
                 XF_SIZE_INVERT},
                {
                 "(.*)(\\x33\\xC0\\xF7\\xD0\\x8B\\xFC\\xF2\\xAF\\x57\\x33\\xC9\\xB1(.)\\x90\\x90\\x90\\x90\\x80\\x37(.)\\x47\\xE2\\xFA.*\\xFF\\xFF\\xFF\\xFF)(.*)$",
                 "rosengarten xor",
                 XF_NONE},
                {
                 "(.*)(\\xEB\\x0F\\x8B\\x34\\x24\\x33\\xC9\\x80\\xC1(.)\\x80\\x36(.)\\x46\\xE2\\xFA\\xC3\\xE8\\xEC\\xFF\\xFF\\xFF)(.*)$",
                 "schauenburg xor",
                 XF_NONE},
                {
                 "(.*)(\\xEB\\x02\\xEB\\x05\\xE8\\xF9\\xFF\\xFF\\xFF\\x58\\x83\\xC0\\x1B\\x8D\\xA0\\x01\\xFC\\xFF\\xFF\\x83\\xE4\\xFC\\x8B\\xEC\\x33\\xC9\\x66\\xB9(..)\\x80\\x30(.)\\x40\\xE2\\xFA)(.*)$",
                 "lichtenfels xor",
                 XF_NONE},
                {
                 "(.*)(\\xC9\\x83\\xE9(.)\\xD9\\xEE\\xD9\\x74\\x24\\xF4\\x5B\\x81\\x73\\x13(....)\\x83\\xEB\\xFC\\xE2\\xF4)(.*)$",
                 "Metasploit PexEnvSub",
                 XF_SIZE_INVERT},
                {
                 "(.*)(\\x2B\\xC9\\x83\\xE9(.)\\xE8\\xFF\\xFF\\xFF\\xFF\\xC0\\x5E\\x81\\x76\\x0E(....)\\x83\\xEE\\xFC\\xE2\\xF4)(.*)$",
                 "Metasploit Pex",
                 XF_SIZE_INVERT},
                {
                 "(.*)(\\xEB\\x0E\\x5B\\x4B\\x33\\xC9\\xB1(.)\\x80\\x34\\x0B(.)\\xE2\\xFA\\xEB\\x05\\xE8\\xED\\xFF\\xFF\\xFF)(.*)$",
                 "leimbach xor",
                 XF_NONE},
                {
                 "(.*)(\\xEB.\\xEB.\\xE8.*\\xB1(.).*\\x80..(.).*\\xE2.)(.*)$",
                 "generic mwcollect",
                 XF_NONE}
        };

        if ((regexpIPAddress =
             pcre_compile
             ("([0-9]{1,3})[\\.]([0-9]{1,3})[\\.]([0-9]{1,3})[\\.]([0-9]{1,3})",
              PCRE_DOTALL, &pcreError, (int *)&pcreErrorPos, 0)) == NULL) {
                fprintf(stderr,
                        "binaryInit() could not compile pattern for IP Address Error:\"%s\" at Position %u",
                        pcreError, pcreErrorPos);
                return (-1);
        }
        /*
         * URL regexp
         * this may need to be checked and updated from time to time.
         */
        if ((regexpURL = pcre_compile(".((ht|f)tp(s?))\\://([0-9a-zA-Z\\-]+\\.)+[a-zA-Z]{2,6}(/\\S*)?",
                                      PCRE_DOTALL, &pcreError, (int *)&pcreErrorPos, 0)) == NULL) {
                fprintf(stderr,
                        "binaryInit() could not compile pattern for URL Error:\"%s\" at Position %u",
                        pcreError, pcreErrorPos);
                return (-1);
        }

        if ((regexpGenericXOR = malloc(sizeof(flist_t))) == NULL)
                return (-1);
        flist_init(regexpGenericXOR);

        for (i = 0; i < 17; i++) {
                pcre           *mypcre;
                if ((mypcre =
                     pcre_compile(test[i].PCRE, PCRE_DOTALL, &pcreError,
                                  (int *)&pcreErrorPos, 0)) == NULL) {
                        fprintf(stderr,
                                "binaryInit() could not compile pattern %i\n\t\"%s\"\n\t Error:\"%s\" at Position %u",
                                i, test[i].Name, pcreError, pcreErrorPos);
                        return (-1);
                } else {
                        XORPcreContext *ctx = malloc(sizeof(XORPcreContext));
                        ctx->PCRE = mypcre;
                        ctx->Name = test[i].Name;
                        ctx->options = test[i].options;
                        flist_append(regexpGenericXOR, i, ctx);
                }
        }
        return (0);
}

int binaryGenericXORDecode(anonpacket * packet, struct anonflow *flow, XORPayloadContent * offsets)
{
        unsigned char  *shellcode = packet->data;
        uint32_t        len = packet->dsize;
        int32_t         output[10 * 3];

        flist_node_t   *tmpnode;

        const char     *preload;
        uint32_t        preloadSize;
        const char     *xordecoder;
        uint32_t        xordecoderSize;
        const char     *match;
        char            key = 0;
        uint32_t        longkey = 0;
        uint32_t        keysize;
        uint32_t        codesize = 0, codesizeLen, totalsize;
        XORPcreContext *context;
        uint32_t        i, j;

        int32_t         ipresult = 0;
        int32_t         ipoutput[3 * 10];
        const char     *ipstring;

        if (!offsets)
                return (-1);

        for (tmpnode = flist_head(regexpGenericXOR), i = 0; tmpnode != NULL;
             tmpnode = tmpnode->next, i++) {
                int32_t         result = 0;
                context = (XORPcreContext *) tmpnode->data;
                if ((result =
                     pcre_exec(context->PCRE, 0, (char *)shellcode,
                               len, 0, 0, (int *)output, sizeof(output) / sizeof(int32_t))) > 0) {
                        preloadSize =
                            pcre_get_substring((char *)shellcode,
                                               (int *)output, (int)result, 1, &preload);

                        xordecoderSize =
                            pcre_get_substring((char *)shellcode,
                                               (int *)output, (int)result, 2, &xordecoder);

                        codesizeLen =
                            pcre_get_substring((char *)shellcode,
                                               (int *)output, (int)result, 3, &match);
                        switch (codesizeLen) {
                        case 4:
                                // this is a special case, for dword xor we have to invert the size
                                if (context->options & XF_SIZE_INVERT) {
                                        codesize = 0 - (uint32_t) * ((uint32_t *) match);
                                } else {
                                        codesize = (uint32_t) * ((uint32_t *) match);
                                }
                                break;

                        case 2:
                                codesize = (uint32_t) * ((uint16_t *) match);
                                break;

                        case 1:
                                if (context->options & XF_SIZE_INVERT) {
                                        codesize = 256 - (uint32_t) * ((char *)match);
                                } else {
                                        codesize = (uint32_t) * ((char *)match);
                                }
                                break;
                        }

                        pcre_free_substring(match);

                        keysize =
                            pcre_get_substring((char *)shellcode,
                                               (int *)output, (int)result, 4, &match);

                        offsets->keysize = keysize;
                        switch (keysize) {

                        case 1:
                                key = *((char *)match);
                                offsets->key = key;
                                break;

                        case 4:
                                longkey = *((uint32_t *) match);
                                offsets->longkey = longkey;
                                break;

                        }

                        pcre_free_substring(match);

                        totalsize =
                            pcre_get_substring((char *)shellcode,
                                               (int *)output, (int)result, 5, &match);
                        char           *decodedMessage = malloc(sizeof(char) * totalsize);
                        memcpy(decodedMessage, match, totalsize);
                        pcre_free_substring(match);

                        switch (keysize) {
                        case 1:
                                if (codesize > totalsize)
                                        fprintf(stderr,
                                                "codesize > totalsize - broken shellcode?\n");

                                for (j = 0; j < codesize && j < totalsize; j++)
                                        decodedMessage[j] ^= key;
                                break;

                        case 4:
                                if (codesize * 4 > totalsize)
                                        fprintf(stderr,
                                                "codesize > totalsize - broken shellcode?\n");

                                for (j = 0; j < codesize && (j + 1) * 4 < totalsize; j++)
                                        *(uint32_t *) (decodedMessage + (j * 4)) ^= longkey;
                                break;
                        }

                        char           *newshellcode = (char *)malloc(len * sizeof(char));
                        memset(newshellcode, 0x90, len);
                        memcpy(newshellcode, preload, preloadSize);

                        memcpy(newshellcode + preloadSize + xordecoderSize,
                               decodedMessage, totalsize);
                        /*
                         * Find IP regexp in newshellcode
                         * Calculate offset
                         * Return that offset
                         */

                        if ((ipresult =
                             pcre_exec(regexpIPAddress, 0, newshellcode, len,
                                       0, 0, ipoutput, sizeof(ipoutput) / sizeof(int32_t))) > 0) {
                                offsets->IPLen =
                                    pcre_get_substring(newshellcode,
                                                       (int *)ipoutput, ipresult, 0, &ipstring);

                                offsets->IP = &shellcode[ipoutput[0]];
                                pcre_free_substring(ipstring);
                        }

                        if ((ipresult =
                             pcre_exec(regexpURL, 0, newshellcode, len, 0, 0,
                                       (int *)ipoutput, sizeof(ipoutput) / sizeof(int32_t))) > 0) {
                                offsets->hostLen =
                                    pcre_get_substring(newshellcode,
                                                       (int *)ipoutput, ipresult, 0, &ipstring);
                                offsets->host = &shellcode[ipoutput[0]];
                                pcre_free_substring(ipstring);
                        }

                        pcre_free_substring(preload);
                        pcre_free_substring(xordecoder);

                        free(decodedMessage);
                        free(newshellcode);

                        return (0);
                }
        }
        return (-1);
}

/*
 * Generic wget decoder
 */
int binaryGenericWgetInit()
{
        const char     *urlpcre = ".*(wget.*)$";
        const char     *pcreError;
        int32_t         pcreErrorPos;

        if ((regexpGenericWget =
             pcre_compile(urlpcre, PCRE_DOTALL, &pcreError, (int *)&pcreErrorPos, 0)) == NULL) {
                fprintf(stderr,
                        "Genericwget could not compile pattern \n\t\"%s\"\n\t Error:\"%s\" at Position %u",
                        urlpcre, pcreError, pcreErrorPos);
                return (-1);
        }

        return (0);
}

int
binaryGenericWgetDecode(anonpacket * packet, struct anonflow *flow, struct genericWgetURL *urlParts)
{
        unsigned char  *shellcode = packet->data;
        uint32_t        len = packet->dsize;
        int32_t         piOutput[10 * 3];
        int32_t         iResult = 0;
        const char     *pUrl = NULL;
        char           *htmlenc = NULL, *htmldec = NULL, *url = NULL, *pos = NULL, *tmp = NULL;
        uint32_t        i = 0, j = 0, declen = 0;
        uint32_t        start = 0, stopp = 0;

        if ((iResult =
             pcre_exec(regexpGenericWget, 0, (char *)shellcode, len, 0, 0,
                       (int *)piOutput, sizeof(piOutput) / sizeof(int32_t))) > 0) {

                pcre_get_substring((char *)shellcode, (int *)piOutput, (int)iResult, 1, &pUrl);
                htmlenc = strdup(pUrl);

                pcre_free_substring(pUrl);

                for (i = 0; i < strlen(htmlenc); i++, j++) {
                        if (htmlenc[i] == '%') {
                                if (i + 3 <= strlen(htmlenc)) {
                                        char           *num = malloc(3 * sizeof(char));
                                        char            thisbyte;

                                        memset(num, 0, 3);
                                        memcpy(num, &htmlenc[i + 1], 2);        //htmlenc.substr(i+1,2);

                                        thisbyte = (char)strtol(num, NULL, 16);
                                        i += 2;
                                        htmldec = realloc(htmldec, ++declen);   // htmldec += thisbyte;
                                        htmldec[declen - 1] = thisbyte;
                                }
                        } else {
                                htmldec = realloc(htmldec, ++declen);
                                htmldec[declen - 1] = htmlenc[i];       // htmldec += htmlenc[i];
                        }
                }

                htmldec = realloc(htmldec, declen + 1);
                htmldec[declen + 1] = '\0';

                i = 4;

                while (htmldec[i] == ' ') {
                        i++;
                }

                start = i;

                while (htmldec[i] != '&' && htmldec[i] != ';') {
                        i++;
                }
                stopp = i;

                url = malloc(sizeof(char) * (stopp - start + 1));
                memset(url, 0, (stopp - start + 1));
                memcpy(url, &htmldec[start], stopp - start);
/*
                if (!strstr (url, "://"))
                {
                        char *tmpurl =
                                malloc (sizeof (char) *
                                        (strlen ("http://") +
                                         (stopp - start + 1)));
                        memset (tmpurl, 0,
                                strlen ("http://") + stopp - start + 1);
                        memcpy (tmpurl, "http://", strlen ("http://"));
                        strcat (tmpurl, url);
                        free (url);
                        url = tmpurl;
                }
*/
                for (i = 0; i < strlen(url); i++) {
                        if (isprint(url[i]) == 0) {
                                fprintf(stderr, "wget url contained unprintable chars\n");
                                return (-1);
                        }
                }

                fprintf(stderr, "decoded URL : %s\n", url);
                /*
                 * Split the URL into its parts.
                 */
                if (!urlParts)
                        return (-1);

                memset(urlParts, 0, sizeof(struct genericWgetURL));

                urlParts->startOffset = piOutput[0];
                urlParts->endOffset = urlParts->startOffset;
                urlParts->decodedurl = url;

                i = 0;
                j = strlen(url);
                pos = url;
                // Protocol
                if ((tmp = strstr(pos, "://")) != NULL) {
                        urlParts->protocol = (unsigned char *)pos;
                        *tmp = '\0';
                        urlParts->protocolLen = strlen(pos);
                        *tmp = ':';
                        pos = tmp + strlen("://");
                        urlParts->endOffset += urlParts->protocolLen;
                }
                // User/Host data
                if ((tmp = strchr(pos, '@')) != NULL) {
                        urlParts->user = (unsigned char *)pos;
                        *tmp = '\0';
                        urlParts->userLen = strlen(pos);
                        *tmp = '@';
                        pos = tmp + 1;
                        urlParts->endOffset += urlParts->userLen;

                        // Password
                        if ((tmp = strchr((char *)urlParts->user, ':')) != NULL) {
                                urlParts->pass =
                                    (unsigned char *)strchr((char *)urlParts->user, '@') + 1;
                                *tmp = '\0';
                                urlParts->passLen = strlen((char *)urlParts->pass);
                                *tmp = ':';
                                pos = tmp + 1;
                                urlParts->endOffset += urlParts->passLen;
                        }
                }
                // Port
                if ((tmp = strchr(pos, '/')) != NULL) {
                        char           *tmp2 = tmp;
                        urlParts->host = (unsigned char *)pos;
                        if ((tmp = strchr((char *)urlParts->host, ':')) != NULL) {
                                urlParts->port = (unsigned char *)tmp + 1;
                                *tmp = '\0';
                                urlParts->hostLen = strlen((char *)urlParts->host);
                                *tmp = ':';
                                *tmp2 = '\0';
                                urlParts->portLen = strlen((char *)urlParts->port);
                                *tmp2 = '/';
                                urlParts->endOffset += urlParts->hostLen + urlParts->portLen;
                        }
                        *tmp2 = '\0';
                        urlParts->hostLen = strlen((char *)urlParts->host);
                        *tmp2 = '/';
                        pos = tmp2 + 1;
                        urlParts->endOffset += urlParts->hostLen;
                }

                if ((tmp = strchr(pos, '/')) != NULL) {
                        urlParts->path = (unsigned char *)tmp + 1;
                        urlParts->pathLen = strlen((char *)urlParts->path);
                        urlParts->endOffset += urlParts->pathLen;
                }
                // Directory
                if (urlParts->path != NULL) {
                        if ((tmp = strrchr((char *)urlParts->path, '/')) != NULL) {
                                urlParts->dir = urlParts->path;
                                *tmp = '\0';
                                urlParts->dirLen = strlen((char *)urlParts->dir);
                                *tmp = '/';
                        }
                        // File
                        if ((tmp = strrchr((char *)urlParts->path, '/')) != NULL) {
                                urlParts->file = (unsigned char *)tmp + 1;
                                urlParts->fileLen = strlen((char *)urlParts->file);
                        } else if (urlParts->dirLen == 0) {
                                urlParts->file = urlParts->path;
                        }
                }

                return (0);
        }
        return (-1);
}

/*
 * stuttgart-shellcode
 */
int binaryStuttgartInit()
{
        const char     *stuttgart =
            "\\x50\\x50\\x68(....)\\x68\\x02\\x00"
            "(..)\\x8B\\xFC\\x50\\x6A\\x01\\x6A\\x02\\xFF"
            "\\x55\\x20\\x8B\\xD8\\x6A\\x10\\x57\\x53\\xFF\\x55"
            "\\x24\\x85\\xC0\\x75\\x59\\xC7\\x45\\x00(....)"
            "\\x50\\x6A\\x04\\x55\\x53\\xFF\\x55\\x2C";

        const char     *pcreError;
        int32_t         pcreErrorPos;
        if ((stuttgartPattern =
             pcre_compile(stuttgart, PCRE_DOTALL, &pcreError, (int *)&pcreErrorPos, 0)) == NULL) {
                fprintf(stderr,
                        "Stuttgart could not compile pattern \n\t\"%s\"\n\t Error:\"%s\" at Position %u",
                        stuttgart, pcreError, pcreErrorPos);
                return (-1);
        }
        return (0);
}

int binaryStuttgartDecode(anonpacket * packet, struct anonflow *flow, stuttgartLink * link)
{
        char           *shellcode = (char *)packet->data;
        uint32_t        len = packet->dsize;

        int32_t         ovec[10 * 3];
        int32_t         matchCount;

        if (!link)
                return (-1);

        if ((matchCount =
             pcre_exec(stuttgartPattern, 0, (char *)shellcode, len, 0, 0,
                       (int *)ovec, sizeof(ovec) / sizeof(int32_t))) > 0) {
                uint16_t        netPort, port;
                char            ipv4_addr_str[INET_ADDRSTRLEN] = {0};
                struct in_addr  address;
                const char     *match;
                unsigned char   authKey[4];

                pcre_get_substring((char *)shellcode, (int *)ovec, (int)matchCount, 1, &match);
                memcpy(&address, match, 4);
                pcre_free_substring(match);
                link->host = &shellcode[ovec[0]];

                pcre_get_substring((char *)shellcode, (int *)ovec, (int)matchCount, 2, &match);
                memcpy(&netPort, match, 2);
                port = ntohs(netPort);
                pcre_free_substring(match);
                link->port = &shellcode[ovec[2]];

                pcre_get_substring((char *)shellcode, (int *)ovec, (int)matchCount, 3, &match);
                memcpy(authKey, match, 4);
                pcre_free_substring(match);
                link->authkey = &shellcode[ovec[4]];

                fprintf(stderr,
                        "Link (from stuttgart-shellcode) host found [%s:%d, key 0x%02x%02x%02x%02x.]\n",
                        inet_ntop(AF_INET, &address, ipv4_addr_str, INET_ADDRSTRLEN), port,
                        authKey[0], authKey[1], authKey[2], authKey[3]);

                return (0);
        }
        return (-1);

}

/*
 * wuerzburg-shellcode
 */
int binaryWuerzburgInit()
{
        /*
           0040200c   eb 27            jmp short wuerzbur.00402035
           0040200e   90               nop
           0040200f   90               nop
           00402010   90               nop
           00402011   90               nop
           00402012   90               nop
           00402013   90               nop
           00402014   5d               pop ebp
           00402015   33c9             xor ecx,ecx
           00402017   66:b9 2502       mov cx,225
           0040201b   8d75 05          lea esi,dword ptr ss:[ebp+5]
           0040201e   8bfe             mov edi,esi
           00402020   8a06             mov al,byte ptr ds:[esi]
           00402022   3c 99            cmp al,99
           00402024   75 05            jnz short wuerzbur.0040202b
           00402026   46               inc esi
           00402027   8a06             mov al,byte ptr ds:[esi]
           00402029   2c 30            sub al,30
           0040202b   46               inc esi
           0040202c   34 99            xor al,99
           0040202e   8807             mov byte ptr ds:[edi],al
           00402030   47               inc edi
           00402031  ^e2 ed            loopd short wuerzbur.00402020
           00402033   eb 0a            jmp short wuerzbur.0040203f
           00402035   e8 daffffff      call wuerzbur.00402014
         */
        const char     *wuerzburg =
            "\\xEB\\x27(..)(....)\\x5D\\x33\\xC9\\x66\\xB9..\\x8D"
            "\\x75\\x05\\x8B\\xFE\\x8A\\x06\\x3C.\\x75\\x05"
            "\\x46\\x8A\\x06\\x2C.\\x46\\x34.\\x88\\x07"
            "\\x47\\xE2\\xED\\xEB\\x0A\\xE8\\xDA\\xFF\\xFF\\xFF";

        const char     *pcreError;
        int32_t         pcreErrorPos;
        if ((wuerzburgPattern =
             pcre_compile(wuerzburg, PCRE_DOTALL, &pcreError, (int *)&pcreErrorPos, 0)) == NULL) {
                fprintf(stderr,
                        "binaryWuerzburgInit could not compile pattern \n\t\"%s\"\n\t Error:\"%s\" at Position %u",
                        wuerzburg, pcreError, pcreErrorPos);
                return (-1);
        }
        return (0);
}

int binaryWuerzburgDecode(anonpacket * packet, struct anonflow *flow, wuerzburgLink * link)
{
        char           *shellcode = (char *)packet->data;
        uint32_t        len = packet->dsize;

        int32_t         ovec[10 * 3];
        int32_t         matchCount;

        if (!link)
                return (-1);

        if ((matchCount =
             pcre_exec(wuerzburgPattern, 0, (char *)shellcode, len, 0, 0, (int *)ovec,
                       sizeof(ovec) / sizeof(int32_t))) > 0) {
                uint16_t        netPort, port;
                uint32_t        address;
                const char     *match;

                pcre_get_substring((char *)shellcode, (int *)ovec, (int)matchCount, 1, &match);
                memcpy(&netPort, match, 2);
                port = ntohs(netPort);
                pcre_free_substring(match);
                link->port = &shellcode[ovec[0]];

                pcre_get_substring((char *)shellcode, (int *)ovec, (int)matchCount, 2, &match);
                memcpy(&address, match, 4);
                pcre_free_substring(match);
                link->ip = &shellcode[ovec[2]];

                address ^= 0xaaaaaaaa;

/*              logInfo("Wuerzburg transfer waiting at %s:%d.\n",
                        inet_ntoa(*(in_addr *)&address), port);

                char *url;

                asprintf(&url,"csend://%s:%d",inet_ntoa(*(in_addr *)&address), port);
                free(url);
*/
                return (0);
        }
        return (-1);
}

int binaryKonstanzInit()
{
        /*
           00402003   66:b9 0501       mov cx,105
           00402007   e8 ffffffff      call konstanz.0040200b
           0040200b   (ff)c1           inc ecx                         ; note: ff in parenthesis overlaps with previous instruction!
           0040200d   5e               pop esi
           0040200e   304c0e 07        xor byte ptr ds:[esi+ecx+7],cl  ; xor key is index
           00402012  ^e2 fa            loopd short konstanz.0040200e
         */
        const char     *konstanzDecoder =
            "\\x33\\xC9\\x66\\xB9(..)\\xE8\\xFF\\xFF\\xFF\\xFF\\xC1\\x5E\\x30\\x4C\\x0E\\x07\\xE2\\xFA(.*)";

        const char     *pcreError;
        int32_t         pcreErrorPos;
        if ((konstanzPattern =
             pcre_compile(konstanzDecoder, PCRE_DOTALL, &pcreError, (int *)&pcreErrorPos,
                          0)) == NULL) {
                fprintf(stderr,
                        "KonstanzXOR could not compile pattern \n\t\"%s\"\n\t Error:\"%s\" at Position %u",
                        konstanzDecoder, pcreError, pcreErrorPos);
                return (-1);
        }
        return (0);

}

int binaryKonstanzDecode(anonpacket * packet, struct anonflow *flow, konstanzLink * link)
{
        unsigned char  *shellcode = packet->data;
        uint32_t        len = packet->dsize;

        int32_t         offsets[10 * 3];
        int32_t         result, i = 0;

        const char     *substring;
        uint16_t        payloadLen, payloadSize;
        char           *payload;

        int32_t         ipresult = 0;
        int32_t         ipoutput[3 * 10];
        const char     *ipstring;

        if ((result =
             pcre_exec(konstanzPattern, 0, (char *)shellcode, len, 0, 0, (int *)offsets,
                       sizeof(offsets) / sizeof(int32_t))) > 0) {
                pcre_get_substring((char *)shellcode, (int *)offsets, (int)result, 1, &substring);
                payloadLen = *((uint16_t *) substring);
                payloadLen += 1;
                pcre_free_substring(substring);

                payloadSize =
                    pcre_get_substring((char *)shellcode, (int *)offsets, (int)result, 2,
                                       &substring);

                if (payloadSize < payloadLen) {
                        pcre_free_substring(substring);
                        return (-1);
                }

                payload = (char *)malloc((uint32_t) payloadLen);
                memcpy(payload, substring, (uint32_t) payloadLen);
                pcre_free_substring(substring);

                fprintf(stderr, "Found konstanzbot XOR decoder, payload is 0x%04x bytes long.\n",
                        (uint32_t) payloadLen);

                for (i = 0; i < payloadLen; i++)
                        payload[i] ^= (i + 1);

                /*
                 * Find IP regexp in newshellcode
                 * Calculate offset
                 * Return that offset
                 */
                if ((ipresult =
                     pcre_exec(regexpIPAddress, 0, payload, payloadLen,
                               0, 0, ipoutput, sizeof(ipoutput) / sizeof(int32_t))) > 0) {
                        link->IPLen =
                            pcre_get_substring(payload, (int *)ipoutput, ipresult, 0, &ipstring);
                        link->IP = &shellcode[ipoutput[0]];
                        pcre_free_substring(ipstring);
                }

                if ((ipresult =
                     pcre_exec(regexpURL, 0, payload, payloadLen, 0, 0,
                               (int *)ipoutput, sizeof(ipoutput) / sizeof(int32_t))) > 0) {
                        link->hostLen =
                            pcre_get_substring(payload, (int *)ipoutput, ipresult, 0, &ipstring);
                        link->host = &shellcode[ipoutput[0]];
                        pcre_free_substring(ipstring);
                }

                free(payload);
                return (0);
        }
        return (-1);
}
