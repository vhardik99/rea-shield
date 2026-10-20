// @rea-protect
export function compute(x, y) {
  return (() => {
    const _args = [x, y],
      _s = [];
    for (const _i of [["arg", 0], ["arg", 1], ["const", 2], ["*"], ["+"], ["const", 3], ["arg", 0], ["const", 1], ["-"], ["/"], ["-"], ["const", 5], ["neg"], ["+"], ["const", 0.5], ["+"]]) {
      const _o = _i[0];
      if (_o === "const") _s.push(_i[1]);else if (_o === "arg") _s.push(_args[_i[1]]);else if (_o === "neg") {
        _s[_s.length - 1] = -_s[_s.length - 1];
      } else {
        const _a = _s.pop(),
          _b = _s.pop();
        _s.push(_o === "+" ? _b + _a : _o === "-" ? _b - _a : _o === "*" ? _b * _a : _b / _a);
      }
    }
    return _s[0];
  })();
}
