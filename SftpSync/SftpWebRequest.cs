/*
 * Created by SharpDevelop.
 * User: Vitaly
 * Date: 20.12.2016
 * Time: 21:43
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.IO;
using Renci.SshNet;
using System.Net;
using KeePassLib.Serialization;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using Renci.SshNet.Common;

namespace SftpSync
{
    /// <summary>
    /// Description of SftpWebRequest.
    /// </summary>
    public class SftpWebRequest : WebRequest, IHasIocProperties
    {

        readonly Uri m_uri;
        List<byte> m_reqBody = new List<byte>();
        byte[] m_fingerprint;
        public override Uri RequestUri
        {
            get
            {
                return m_uri;
            }
        }
        string m_strMethod = string.Empty;
        public override string Method
        {
            get { return m_strMethod; }
            set
            {
                if (value == null) throw new ArgumentNullException("value");
                m_strMethod = value;
            }
        }
        WebHeaderCollection m_whcHeaders = new WebHeaderCollection();
        public override WebHeaderCollection Headers
        {
            get { return m_whcHeaders; }
            set
            {
                if (value == null) throw new ArgumentNullException("value");
                m_whcHeaders = value;
            }
        }
        long m_lContentLength;
        public override long ContentLength
        {
            get { return m_lContentLength; }
            set
            {
                if (value < 0) throw new ArgumentOutOfRangeException("value");
                m_lContentLength = value;
            }
        }
        string m_strContentType = string.Empty;
        public override string ContentType
        {
            get { return m_strContentType; }
            set
            {
                if (value == null) throw new ArgumentNullException("value");
                m_strContentType = value;
            }
        }
        ICredentials m_cred;
        public override ICredentials Credentials
        {
            get { return m_cred; }
            set { m_cred = value; }
        }
        bool m_bPreAuth = true;
        public override bool PreAuthenticate
        {
            get { return m_bPreAuth; }
            set { m_bPreAuth = value; }
        }
        IWebProxy m_prx;
        public override IWebProxy Proxy
        {
            get { return m_prx; }
            set { m_prx = value; }
        }
        IocProperties m_props = new IocProperties();
        public IocProperties IOConnectionProperties
        {
            get { return m_props; }
            set
            {
                if (value == null) { Debug.Assert(false); return; }
                m_props = value;
            }
        }


        public SftpWebRequest(Uri uri)
        {
            if (uri == null) throw new ArgumentNullException("uri");
            m_uri = uri;
        }

        public override Stream GetRequestStream()
        {
            m_reqBody.Clear();
            return new CopyMemoryStream(m_reqBody);
        }

        public override WebResponse GetResponse()
        {
            NetworkCredential cred = (m_cred as NetworkCredential);
            string strUser = ((cred != null) ? cred.UserName : null);
            string strPassword = ((cred != null) ? cred.Password : null);

            BaseClient m_Client = null;

            int l_port = m_uri.Port == -1 ? 22 : m_uri.Port;

            Uri uriTo = null;
            if (m_strMethod == IOConnection.WrmMoveFile)
            {
                uriTo = new Uri(m_whcHeaders.Get(IOConnection.WrhMoveFileTo));
            }

            MemoryStream reqStream = null;
            if (m_reqBody.Count > 0) reqStream = new MemoryStream(m_reqBody.ToArray());



            KeyboardInteractiveAuthenticationMethod v_kauth = new KeyboardInteractiveAuthenticationMethod(strUser);
            v_kauth.AuthenticationPrompt += SftpWebRequest_AuthenticationPrompt;
            PasswordAuthenticationMethod v_pauth = new PasswordAuthenticationMethod(strUser, strPassword);

            ConnectionInfo n_con_info = new ConnectionInfo(m_uri.Host, l_port, strUser, v_pauth, v_kauth);
            m_Client = new SftpClient(n_con_info);

            if (m_props.Get("HostKey") != null)
            {
                string[] v_ssh_dss_parts = m_props.Get("HostKey").Split(':');
                if (v_ssh_dss_parts.Length != 16) throw new Exception("Input incorrect host fingerprint. Check it. Must bu like: 12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef");
                List<byte> v_ssh_dss_parts_b = new List<byte>();
                foreach (string str in v_ssh_dss_parts)
                {
                    try
                    {
                        v_ssh_dss_parts_b.Add(byte.Parse(str, System.Globalization.NumberStyles.AllowHexSpecifier));
                    }
                    catch (Exception)
                    {
                        throw new Exception("Input incorrect host fingerprint. Check it. Must bu like: 12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef");

                    }
                }
                m_fingerprint = v_ssh_dss_parts_b.ToArray();
                m_Client.HostKeyReceived += M_Client_HostKeyReceived;

            }

            Console.WriteLine ("Request: " + m_strMethod + ", " + m_uri.AbsoluteUri);
            return new SftpWebResponse(m_Client, m_strMethod, m_uri, uriTo, reqStream);
        }



        void SftpWebRequest_AuthenticationPrompt(object sender, AuthenticationPromptEventArgs e)
        {
            foreach (AuthenticationPrompt prompt in e.Prompts)
            {
                if (prompt.Request.IndexOf("Password:", StringComparison.InvariantCultureIgnoreCase) != -1)
                {
                    prompt.Response = (m_cred as NetworkCredential).Password;
                }
            }
        }

        void M_Client_HostKeyReceived(object sender, HostKeyEventArgs e)
        {
            e.CanTrust = e.FingerPrint.SequenceEqual(m_fingerprint) ? true : false;
        }
    }
}
