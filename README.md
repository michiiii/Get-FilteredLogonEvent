# Get-LogonEventDetails PowerShell Function

## Overview

The `Get-LogonEventDetails` function retrieves logon events from the Windows Security log, excluding LogonType 3 and the "SYSTEM" account. It's particularly useful for detecting if service accounts are connecting to your machine in an insecure manner.

## Features

- Filters out LogonType 3 events and events with the "SYSTEM" account name.
- Allows users to specify the number of days back from which to retrieve events.
- Outputs a table with date, logon type, account name, and account domain.

## Prerequisites

- Requires elevated permissions to access the Windows Security log.

## Installation

1. Clone this repository.
2. Navigate to the directory and import the function.
3. Use as described in the usage section.

## Usage

To retrieve logon events from the default last 2 days:

```
Get-LogonEventDetails
```

To retrieve logon events from the last 5 days:

```
Get-LogonEventDetails -days 5
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
