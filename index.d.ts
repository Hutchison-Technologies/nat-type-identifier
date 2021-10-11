export interface GetNatTypeOptions {
  logsEnabled?: boolean;
  sampleCount?: number;
  stunHost?: string;
}

function getNatType(options: GetNatTypeOptions): Promise<NatType>

export type NatType =
  "Blocked" |
  "Open Internet" |
  "Full Cone" |
  "Symmetric UDP Firewall" |
  "Restric NAT" |
  "Restric Port NAT" |
  "Symmetric NAT"

export = getNatType
