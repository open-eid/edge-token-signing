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

var portDict = {};
browser.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    var id = sender.tab.id;
    try {
        switch (request.type) {
            case "connect":
                var port = browser.runtime.connectNative("ee.ria.esteid");
                if (!port)
                    throw new Error("Failed to connect port");
                port.onMessage.addListener(function (message) {
                    var resp = JSON.parse(message);
                    resp['src'] = 'background.js';
                    resp['extension'] = browser.runtime.getManifest().version;
                    browser.tabs.sendMessage(id, resp);
                });
                port.onDisconnect.addListener(function () {
                    delete portDict[id];
                });
                portDict[id] = port;
                break;
            case "disconnect":
                if (portDict[id]) {
                    portDict[id].disconnect();
                    delete portDict[id];
                }
                break;
            default:
                if (portDict[id])
                    portDict[id].postMessage(request);
                break;
        }
    }
    catch (e) {
        browser.tabs.sendMessage(id, { result: "technical_error", message: e.message });
    }
    return true;
});