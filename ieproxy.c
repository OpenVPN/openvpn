/*
 *  Copyright (C) 2004 Ewan Bhamrah Harley <code@ewan.info>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "syshead.h"

#ifdef WIN32

#include <wininet.h>
#include <malloc.h>

LPCTSTR getIeHttpProxyError=NULL;

/* getIeHttpProxy fetches the current IE proxy settings for http */

LPCTSTR getIeHttpProxy()
{
  DWORD psize=0;
  INTERNET_PROXY_INFO *pinfo;
  LPTSTR proxyString;
  LPTSTR p;
  LPTSTR q;
  unsigned int len;
	
  /* first see how big a buffer we need for the IPO structure */
  InternetQueryOption(NULL, INTERNET_OPTION_PROXY, NULL, &psize);
  if(!psize)
  {
    getIeHttpProxyError="InternetQueryOption failed to return buffer size";
    return(NULL);
  }

  /* allocate memory for IPO */
  pinfo =  malloc (psize*sizeof(TCHAR));
  if (pinfo == NULL)
  {
    getIeHttpProxyError="malloc failed (1)";
    return(NULL);
  }

  /* now run the real query */
  if(!InternetQueryOption(NULL, INTERNET_OPTION_PROXY, (LPVOID) pinfo, &psize))
  {
    getIeHttpProxyError="InternetQueryOption() failed to find proxy info";
    free(pinfo);
    return(NULL);
  }


  /* see what sort of result we got */
	
  if(pinfo->dwAccessType == INTERNET_OPEN_TYPE_DIRECT)
  {
    /* No proxy configured */
    free(pinfo);
    return("");
  }
  else if(pinfo->dwAccessType == INTERNET_OPEN_TYPE_PROXY)
  {
    /* we have a proxy - now parse result string */
    /* if result string does NOT contain an '=' sign then */
    /* there is a single proxy for all protocols          */
    for (p=(LPTSTR)pinfo->lpszProxy; *p && *p != '='; p++);
    if(!*p)
    {
      /* single proxy */
      /* allocate a new string to return */
      len = 1+strlen(pinfo->lpszProxy);
      proxyString = malloc (len*sizeof(TCHAR));
      if (proxyString == NULL)
      {
        getIeHttpProxyError="malloc failed (2)";
        free(pinfo);
        return(NULL);
      }
      strncpy(proxyString, pinfo->lpszProxy,len);
      proxyString[len]=0;
      free(pinfo);
      return(proxyString);
    }
    else
    {
      /* multiple space seperated proxies defined in the form */
      /* protocol=proxyhost[:port]                            */
      /* we want the one marked "http=", if any.              */
      p=(LPTSTR)pinfo->lpszProxy;
      while(*p && strncmp(p, "http=", 5))
      {
        for(; *p && *p != ' '; p++);
        if(*p) p++;
      }
      if(*p)
      {
        /* found the proxy */
        p+=5;
        for(q=p; *q && *q != ' '; q++);
        /* allocate a buffer for the proxy information */
        len=1+(q-p);
        proxyString=malloc(len*sizeof(TCHAR));
        if(proxyString==NULL)
        {
          getIeHttpProxyError="malloc failed (3)";
          free(pinfo);
          return(NULL);
        }
        strncpy(proxyString, p, len);
        proxyString[len]=0;
        free(pinfo);
        return(proxyString);
      }
      else
      {
        /* No http proxy in list */
        free(pinfo);
        return("");
      }
    }
  }
  else
  {
    /* InternetQueryOption returned a proxy type we don't know about*/
    getIeHttpProxyError="Unknown Proxy Type";
    free(pinfo);
    return(NULL);
  }
}
#else
#ifdef _MSC_VER  /* Dummy function needed to avoid empty file compiler warning in Microsoft VC */
static void dummy (void) {}
#endif
#endif				/* WIN32 */
