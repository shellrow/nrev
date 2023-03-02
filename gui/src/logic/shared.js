export const sleep = msec => new Promise(resolve => setTimeout(resolve, msec));

export function isValidIPaddress(ipaddress) 
{
    if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress))
    {
        return true;
    }
    return false;
}

export function isValidIPv4Address(ipaddress)
{
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress))
  {
    return true;
  }
  return false;
}

export function isValidIPv6Address(ipaddress)
{
  if (/^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/.test(ipaddress))
  {
    return true;
  }
  return false;
}

export function isValidHostname(value) {
    if (typeof value !== 'string'){
        return false;
    } 

    const validHostnameChars = /^[a-zA-Z0-9-.]{1,253}\.?$/g
    if (!validHostnameChars.test(value)) {
      return false
    }
  
    if (value.endsWith('.')) {
      value = value.slice(0, value.length - 1)
    }
  
    if (value.length > 253) {
      return false
    }
  
    const labels = value.split('.')
  
    const isValid = labels.every(function (label) {
      const validLabelChars = /^([a-zA-Z0-9-]+)$/g
  
      const validLabel = (
        validLabelChars.test(label) &&
        label.length < 64 &&
        !label.startsWith('-') &&
        !label.endsWith('-')
      )
      return validLabel
    }) 
    return isValid
}
