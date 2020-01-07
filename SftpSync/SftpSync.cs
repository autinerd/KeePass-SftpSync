﻿/*
 * Created by SharpDevelop.
 * User: Vitaly
 * Date: 19.12.2016
 * Time: 20:12
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Collections.Generic;

using KeePass.Plugins;
using KeePassLib.Serialization;
using KeePass.Ecas;
using KeePassLib;

namespace SftpSync
{
    /// <summary>
    /// Description of MyClass.
    /// </summary>
    public sealed class SftpSyncExt : Plugin
    {
        IPluginHost m_host;
        static bool m_bPropRegistered;
        SftpWebRequestCreator m_sftpCr;



        public override bool Initialize (IPluginHost host)
        {
            m_host = host;
            m_sftpCr = new SftpWebRequestCreator ();
            m_sftpCr.Register ();
            RegisterIocProperties ();

            return true;
        }

        public override void Terminate ()
        {
            m_host = null;
        }

        static void RegisterIocProperties()
        {
            if (m_bPropRegistered) return;
            m_bPropRegistered = true;

            string[] vScpSftp = { "SCP", "SFTP" };



            IocPropertyInfoPool.Add(new IocPropertyInfo("HostKey",
                            typeof(string), "Fingerprint of expected SSH host key", vScpSftp));

            /* later...
            IocPropertyInfoPool.Add(new IocPropertyInfo("PrivateKey",
				typeof(string), "SSH private key path", vScpSftp));
			IocPropertyInfoPool.Add(new IocPropertyInfo("Passphrase",
				typeof(string), "Passphrase for encrypted private keys and client certificates",
                vScpSftp));
                */
        }

    }
}