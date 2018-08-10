/*
 * Edge token signing extension
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

using System;
using System.Collections.Generic;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.ApplicationModel.AppService;
using Windows.ApplicationModel.Background;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace TokenSigning
{
    /// <summary>
    /// Provides application-specific behavior to supplement the default Application class.
    /// </summary>
    sealed partial class App : Application
    {
        private bool desktopBridgeAppLaunched = true;
        static int connectionIndex = 0;
        static int desktopBridgeConnectionIndex = 0;
        static Dictionary<int, AppServiceConnection> connections = new Dictionary<int, AppServiceConnection>();
        static Dictionary<int, AppServiceConnection> desktopBridgeConnections = new Dictionary<int, AppServiceConnection>();
        static Dictionary<int, BackgroundTaskDeferral> appServiceDeferrals = new Dictionary<int, BackgroundTaskDeferral>();
        static Dictionary<int, BackgroundTaskDeferral> desktopBridgeAppServiceDeferrals = new Dictionary<int, BackgroundTaskDeferral>();
        static Object thisLock = new Object();

        /// <summary>
        /// Initializes the singleton application object.  This is the first line of authored code
        /// executed, and as such is the logical equivalent of main() or WinMain().
        /// </summary>
        public App()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Initializes the app service on the host process 
        /// </summary>
        protected async override void OnBackgroundActivated(BackgroundActivatedEventArgs args)
        {
            base.OnBackgroundActivated(args);
            IBackgroundTaskInstance taskInstance = args.TaskInstance;
            if (taskInstance.TriggerDetails is AppServiceTriggerDetails)
            {
                AppServiceTriggerDetails appService = taskInstance.TriggerDetails as AppServiceTriggerDetails;
                if (appService.CallerPackageFamilyName == Package.Current.Id.FamilyName) // App service connection from desktopBridge App
                {
                    BackgroundTaskDeferral desktopBridgeAppServiceDeferral = taskInstance.GetDeferral(); // Get a deferral so that the service isn't terminated.
                    taskInstance.Canceled += (IBackgroundTaskInstance sender, BackgroundTaskCancellationReason reason) =>
                    {
                        CloseConnection((sender.TriggerDetails as AppServiceTriggerDetails).AppServiceConnection, false);
                    };
                    AppServiceConnection desktopBridgeConnection = appService.AppServiceConnection;
                    desktopBridgeConnection.RequestReceived += OndesktopBridgeAppServiceRequestReceived;
                    desktopBridgeConnection.ServiceClosed += (AppServiceConnection sender, AppServiceClosedEventArgs args2) =>
                    {
                        CloseConnection(sender, false);
                    };
                    lock (thisLock)
                    {
                        desktopBridgeConnection.AppServiceName = desktopBridgeConnectionIndex.ToString();
                        desktopBridgeConnections.Add(desktopBridgeConnectionIndex, desktopBridgeConnection);
                        desktopBridgeAppServiceDeferrals.Add(desktopBridgeConnectionIndex, desktopBridgeAppServiceDeferral);
                        desktopBridgeConnectionIndex++;
                    }
                }
                else // App service connection from Edge browser
                {
                    BackgroundTaskDeferral appServiceDeferral = taskInstance.GetDeferral(); // Get a deferral so that the service isn't terminated.
                    taskInstance.Canceled += (IBackgroundTaskInstance sender, BackgroundTaskCancellationReason reason) =>
                    {
                        CloseConnection((sender.TriggerDetails as AppServiceTriggerDetails).AppServiceConnection, true);
                    };
                    AppServiceConnection connection = appService.AppServiceConnection;
                    connection.RequestReceived += OnAppServiceRequestReceived;
                    connection.ServiceClosed += (AppServiceConnection sender, AppServiceClosedEventArgs args2) =>
                    {
                        CloseConnection(sender, true);
                    };
                    lock (thisLock)
                    {
                        connection.AppServiceName = connectionIndex.ToString();
                        connections.Add(connectionIndex, connection);
                        appServiceDeferrals.Add(connectionIndex, appServiceDeferral);
                        connectionIndex++;
                    }

                    try
                    {
                        // Make sure the HostBackend.exe is in your AppX folder, if not rebuild the solution
                        await FullTrustProcessLauncher.LaunchFullTrustProcessForCurrentAppAsync();
                    }
                    catch (Exception)
                    {
                        desktopBridgeAppLaunched = false;
                        MessageDialog dialog = new MessageDialog("Rebuild the solution and make sure the HostBackend.exe is in your AppX folder");
                        await dialog.ShowAsync();
                    }
                }
            }
        }

        /// <summary>
        /// Receives message from Extension (via Edge)
        /// </summary>
        private async void OnAppServiceRequestReceived(AppServiceConnection sender, AppServiceRequestReceivedEventArgs args)
        {
            AppServiceDeferral messageDeferral = args.GetDeferral();
            try
            {
                if (desktopBridgeAppLaunched)
                {
                    // Send message to the desktopBridge component and wait for response
                    AppServiceConnection desktopBridgeConnection = desktopBridgeConnections[Int32.Parse(sender.AppServiceName)];
                    AppServiceResponse desktopBridgeResponse = await desktopBridgeConnection.SendMessageAsync(args.Request.Message);
                    await args.Request.SendResponseAsync(desktopBridgeResponse.Message);
                }
                else
                    throw new Exception("Failed to launch desktopBridge App!");
            }
            finally
            {
                messageDeferral.Complete();
            }
        }

        /// <summary>
        /// Receives message from desktopBridge App
        /// </summary>
        private async void OndesktopBridgeAppServiceRequestReceived(AppServiceConnection sender, AppServiceRequestReceivedEventArgs args)
        {
            AppServiceDeferral messageDeferral = args.GetDeferral();
            try
            {
                await connections[Int32.Parse(sender.AppServiceName)].SendMessageAsync(args.Request.Message);
            }
            finally
            {
                messageDeferral.Complete();
            }
        }

        private void CloseConnection(AppServiceConnection connection, bool closeAppConnection)
        {
            int index = Int32.Parse(connection.AppServiceName);
            if (closeAppConnection)
            {
                desktopBridgeConnections[index].Dispose();
                desktopBridgeConnections.Remove(index);
            }
            else
            {
                connections[index].Dispose();
                connections.Remove(index);
            }
            BackgroundTaskDeferral appServiceDeferral = appServiceDeferrals[index];
            appServiceDeferrals.Remove(index);
            BackgroundTaskDeferral desktopBridgeAppServiceDeferral = desktopBridgeAppServiceDeferrals[index];
            desktopBridgeAppServiceDeferrals.Remove(index);
            if (appServiceDeferral != null)
                appServiceDeferral.Complete();
            if (desktopBridgeAppServiceDeferral != null)
                desktopBridgeAppServiceDeferral.Complete();
        }

        /// <summary>
        /// Invoked when the application is launched normally by the end user.  Other entry points
        /// will be used such as when the application is launched to open a specific file.
        /// </summary>
        /// <param name="e">Details about the launch request and process.</param>
        protected override void OnLaunched(LaunchActivatedEventArgs e)
        {
            Frame rootFrame = Window.Current.Content as Frame;
            if (rootFrame == null)
            {
                rootFrame = new Frame();
                Window.Current.Content = rootFrame;
            }
            if (e.PrelaunchActivated == false)
            {
                if (rootFrame.Content == null)
                    rootFrame.Navigate(typeof(MainPage), e.Arguments);
                Window.Current.Activate();
            }
        }
    }
}
