import * as os from 'os';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import type * as vscode from 'vscode';
import * as path from 'path';

export function getHostName(): string {
    return os.hostname();
}

export function getIpAddress(): string | undefined {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        const ifaceDetails = interfaces[name];
        if (ifaceDetails) {
            for (const iface of ifaceDetails) {
                // Skip over internal (i.e. 127.0.0.1) and non-ipv4 addresses
                if (iface.family === 'IPv4' && !iface.internal) {
                    return iface.address;
                }
            }
        }
    }
}

const AGENT_ID_KEY = 'agentId';

function getSerialNumber(): string | null {
    const platform = os.platform();
    let command: string;

    switch (platform) {
        case 'win32':
            command = 'wmic bios get serialnumber';
            break;
        case 'darwin':
            command = 'ioreg -l | grep IOPlatformSerialNumber';
            break;
        case 'linux':
            // Tries to get system serial, falls back to machine-id, then hostname.
            command =
                '(cat /sys/class/dmi/id/product_serial 2>/dev/null || cat /etc/machine-id 2>/dev/null) | head -n 1';
            break;
        default:
            return null;
    }

    try {
        const stdout = execSync(command, { encoding: 'utf8' });
        let serial = stdout.toString().trim();

        if (platform === 'win32') {
            serial = serial.split('\n').pop()?.trim() || '';
        } else if (platform === 'darwin') {
            serial = serial.split('=').pop()?.replace(/"/g, '').trim() || '';
        }

        // Filter out common placeholder values
        const placeholders = [
            'To be filled by O.E.M.',
            'Default string',
            '',
        ];
        if (serial && !placeholders.includes(serial)) {
            return serial;
        } else {
            return null;
        }
    } catch (error: any) {
        // On error, return null
        return null;
    }
}

function getMacAddress(): string | null {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        const ifaceDetails = interfaces[name];
        if (ifaceDetails) {
            for (const iface of ifaceDetails) {
                // Find the first non-internal, non-zero MAC address
                if (
                    iface.mac &&
                    iface.mac !== '00:00:00:00:00:00' &&
                    !iface.internal
                ) {
                    return iface.mac;
                }
            }
        }
    }
    return null;
}

/**
 * Generates or retrieves a unique agent ID.
 * If we are running as part of the VSCode (production case), then use vscode.env.machineId.
 * Otherwise:
 * It first checks for a stored ID in the provided storage. If not found, it generates a new ID
 * based on the machine's serial number or MAC address. If neither can be found, it creates a
 * random ID. The new ID is then stored for future use if storage is provided.
 * @param storage An optional Memento object (e.g., ExtensionContext.globalState) for storing/retrieving the agent ID.
 * @returns A promise that resolves to the unique agent ID.
 */
export function getAgentId(storage?: vscode.Memento): string {
    try {
        const vscode = require('vscode');
        if (vscode) {
            return vscode.env.machineId;
        }
    } catch (error) {
        // Could not load vscode, proceed with fallback
    }

    if (storage) {
        const storedId = storage.get<string>(AGENT_ID_KEY);
        if (storedId) {
            return storedId;
        }
    }

    let machineId = getSerialNumber();
    if (!machineId) {
        machineId = getMacAddress();
    }

    let agentId: string;
    if (machineId) {
        agentId = crypto.createHash('sha256').update(machineId).digest('hex');
    } else {
        // Fallback to a random ID if no unique identifier could be found
        agentId = crypto
            .createHash('sha256')
            .update(crypto.randomBytes(32))
            .digest('hex');
    }

    if (storage) {
        // We don't have to await - worst case we'll re-run the calculation if wasn't stored yet
        storage.update(AGENT_ID_KEY, agentId);
    }

    return agentId;
}

export function getVSCodeFolder() {
    switch (process.platform) {
        case 'win32':
            return path.join(process.env.APPDATA || '', 'Code', 'User');

        case 'darwin':
            return path.join(os.homedir(), 'Library', 'Application Support', 'Code', 'User');

        case 'linux': {
            // Detect WSL: VS Code settings live on the Windows side
            const isWSL = isRunningInWSL();
            if (isWSL) {
                const winAppData = getWindowsAppDataInWSL();
                if (winAppData) {
                    return path.join(winAppData, 'Code', 'User');
                }
            }
            return path.join(os.homedir(), '.config', 'Code', 'User');
        }

        default:
            throw new Error('Unsupported platform');
    }
}

/**
 * Detect if running inside Windows Subsystem for Linux.
 */
function isRunningInWSL(): boolean {
    try {
        const release = os.release().toLowerCase();
        if (release.includes('microsoft') || release.includes('wsl')) {
            return true;
        }
        // Fallback: check /proc/version
        const fs = require('fs');
        const procVersion = fs.readFileSync('/proc/version', 'utf-8').toLowerCase();
        return procVersion.includes('microsoft') || procVersion.includes('wsl');
    } catch {
        return false;
    }
}

/**
 * Resolve the Windows APPDATA path from inside WSL.
 * Tries common user profile locations under /mnt/c/Users/.
 */
function getWindowsAppDataInWSL(): string | null {
    const fs = require('fs');
    try {
        // Method 1: Use cmd.exe to get APPDATA
        const result = execSync('cmd.exe /C "echo %APPDATA%" 2>/dev/null', { encoding: 'utf-8' }).trim();
        if (result && !result.includes('%APPDATA%')) {
            // Convert Windows path (C:\Users\HP\AppData\Roaming) to WSL path (/mnt/c/Users/HP/AppData/Roaming)
            const wslPath = result
                .replace(/\r/g, '')
                .replace(/^([A-Za-z]):/, (_, drive: string) => `/mnt/${drive.toLowerCase()}`)
                .replace(/\\/g, '/');
            if (fs.existsSync(wslPath)) {
                return wslPath;
            }
        }
    } catch { /* cmd.exe not available */ }

    try {
        // Method 2: Scan /mnt/c/Users/*/AppData/Roaming for Code folder
        const usersDir = '/mnt/c/Users';
        if (fs.existsSync(usersDir)) {
            const users: string[] = fs.readdirSync(usersDir);
            for (const user of users) {
                if (user === 'Public' || user === 'Default' || user === 'Default User' || user === 'All Users') {
                    continue;
                }
                const appData = path.join(usersDir, user, 'AppData', 'Roaming');
                const codeDir = path.join(appData, 'Code', 'User');
                if (fs.existsSync(codeDir)) {
                    return appData;
                }
            }
        }
    } catch { /* /mnt/c not available */ }

    return null;
}
