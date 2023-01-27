// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// Uncomment this line to use console.log
import "hardhat/console.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {IPermissionVault} from "./interfaces/IPermissionVault.sol";

error NotController();
error NotEOA();
error NotEnoughBalance();
error ZeroAmount();
error NotExistToken();

/**
 * Stakes tokens for a certain duration and gets rewards according to their
 * staked shares
 */
contract PermissionVault is
  IPermissionVault,
  IERC721Receiver,
  IERC1155Receiver,
  Ownable,
  AccessControl,
  Pausable,
  ReentrancyGuard
{
  using SafeERC20 for IERC20;

  bytes32 public constant CONTROLLER_ROLE =
    bytes32(keccak256("CONTROLLER_ROLE"));

  /* -------------------------------------------------------------------------- */
  /*                                   Events                                   */
  /* -------------------------------------------------------------------------- */

  /**
   * Emitted when new controller was added
   */
  event AddController(address controller);
  /**
   * Emitted when controller was removed
   */
  event RemoveController(address controller);

  /**
   * Emitted when controller deposited Ether
   */
  event DepositEther(address controller, uint256 amount);
  /**
   * Emitted when controller withdrawed Ether
   */
  event WithdrawEther(address controller, address to, uint256 amount);

  /**
   * Emitted when controller deposited ERC20
   */
  event DepositERC20(address controller, IERC20 token, uint256 amount);
  /**
   * Emitted when controller withdrawed ERC20
   */
  event WithdrawERC20(
    address controller,
    address to,
    IERC20 token,
    uint256 amount
  );

  /**
   * Emitted when controller deposited ERC721
   */
  event DepositERC721(address controller, IERC721 token, uint256 id);
  /**
   * Emitted when controller withdrawed ERC721
   */
  event WithdrawERC721(
    address controller,
    address to,
    IERC721 token,
    uint256 id
  );

  /**
   * Emitted when controller deposited ERC1155
   */
  event DepositERC1155(
    address controller,
    IERC1155 token,
    uint256 id,
    uint256 amount
  );
  /**
   * Emitted when controller withdrawed ERC1155
   */
  event WithdrawERC1155(
    address controller,
    address to,
    IERC1155 token,
    uint256 id,
    uint256 amount
  );

  /* -------------------------------------------------------------------------- */
  /*                                  Modifiers                                 */
  /* -------------------------------------------------------------------------- */

  modifier onlyController() {
    if (!hasRole(CONTROLLER_ROLE, msg.sender)) {
      revert NotController();
    }
    _;
  }

  /* -------------------------------------------------------------------------- */
  /*                             External Functions                             */
  /* -------------------------------------------------------------------------- */

  /**
   * @dev Constructor
   */
  constructor() {
    _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    _setupRole(CONTROLLER_ROLE, msg.sender);
  }

  /**
   * @notice Pause or unpause contract
   * @dev Callable by owner
   * @param newPaused Flag to new paused state
   */
  function setPaused(bool newPaused) external onlyOwner {
    if (newPaused) {
      _pause();
    } else {
      _unpause();
    }
  }

  function addController() external onlyOwner {
    _setupRole(CONTROLLER_ROLE, msg.sender);

    emit AddController(msg.sender);
  }

  function removeController() external onlyOwner {
    revokeRole(CONTROLLER_ROLE, msg.sender);

    emit RemoveController(msg.sender);
  }

  function depositEther() external payable {
    if (msg.value == 0) {
      revert ZeroAmount();
    }

    emit DepositEther(msg.sender, msg.value);
  }

  function withdrawEther(
    address to,
    uint256 amount
  ) external nonReentrant onlyController {
    if (amount > address(this).balance) {
      revert NotEnoughBalance();
    }

    (bool success, ) = to.call{value: amount}("");
    require(success);

    emit WithdrawEther(msg.sender, to, amount);
  }

  function depositERC20(IERC20 token, uint256 amount) external {
    if (amount == 0) {
      revert ZeroAmount();
    }

    token.safeTransferFrom(msg.sender, address(this), amount);
    emit DepositERC20(msg.sender, token, amount);
  }

  function withdrawERC20(
    address to,
    IERC20 token,
    uint256 amount
  ) external onlyController {
    if (amount > token.balanceOf(address(this))) {
      revert NotEnoughBalance();
    }

    token.safeTransfer(to, amount);
    emit WithdrawERC20(msg.sender, to, token, amount);
  }

  function depositERC721(IERC721 token, uint256 id) external {
    token.safeTransferFrom(msg.sender, address(this), id);
    emit DepositERC721(msg.sender, token, id);
  }

  function withdrawERC721(
    address to,
    IERC721 token,
    uint256 id
  ) external onlyController {
    if (token.ownerOf(id) != address(this)) {
      revert NotExistToken();
    }

    token.safeTransferFrom(address(this), to, id);
    emit WithdrawERC721(msg.sender, to, token, id);
  }

  function depositERC1155(IERC1155 token, uint256 id, uint256 amount) external {
    if (amount == 0) {
      revert ZeroAmount();
    }

    token.safeTransferFrom(msg.sender, address(this), id, amount, "");
    emit DepositERC1155(msg.sender, token, id, amount);
  }

  function withdrawERC1155(
    address to,
    IERC1155 token,
    uint256 id,
    uint256 amount
  ) external onlyController {
    if (amount > token.balanceOf(address(this), id)) {
      revert NotEnoughBalance();
    }

    token.safeTransferFrom(address(this), to, id, amount, "");
    emit WithdrawERC1155(msg.sender, to, token, id, amount);
  }

  function onERC721Received(
    address operator,
    address from,
    uint256 tokenId,
    bytes calldata data
  ) external pure override returns (bytes4) {
    return IERC721Receiver.onERC721Received.selector;
  }

  function onERC1155Received(
    address operator,
    address from,
    uint256 id,
    uint256 value,
    bytes calldata data
  ) external pure override returns (bytes4) {
    return IERC1155Receiver.onERC1155Received.selector;
  }

  function onERC1155BatchReceived(
    address operator,
    address from,
    uint256[] calldata ids,
    uint256[] calldata values,
    bytes calldata data
  ) external pure override returns (bytes4) {
    return IERC1155Receiver.onERC1155BatchReceived.selector;
  }
}
