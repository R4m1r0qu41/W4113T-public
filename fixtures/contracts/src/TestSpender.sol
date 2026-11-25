// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @notice Sample spender for the vertical-slice demo: pulls tokens it has
/// been approved for. Exists so approvals have a realistic counterparty.
contract TestSpender {
    event Pulled(address indexed token, address indexed from, uint256 amount);

    function pull(address token, address from, uint256 amount) external {
        require(IERC20(token).transferFrom(from, address(this), amount), "pull failed");
        emit Pulled(token, from, amount);
    }
}
