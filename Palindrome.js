function isPalindrome(palin) {
  palin = palin.toLowerCase().replace(/[^a-z0-9]/g, "");

  for (let i = 0; i < palin.length / 2; i++) {
    if (palin[i] !== palin[palin.length - 1 - i]) {
      return false;
    }
  }

  return true;
}

console.log(isPalindrome("A man, a plan, a canal: Panama"));
