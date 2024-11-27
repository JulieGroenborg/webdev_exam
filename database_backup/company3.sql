-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Vært: mysql
-- Genereringstid: 24. 11 2024 kl. 12:00:58
-- Serverversion: 9.0.1
-- PHP-version: 8.2.8

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `company`
--

-- --------------------------------------------------------

--
-- Struktur-dump for tabellen `items`
--

CREATE TABLE `items` (
  `item_pk` char(36) NOT NULL,
  `item_user_fk` char(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `item_title` varchar(50) NOT NULL,
  `item_price` decimal(5,2) NOT NULL,
  `item_image` varchar(50) DEFAULT NULL,
  `item_created_at` int UNSIGNED DEFAULT NULL,
  `item_deleted_at` int UNSIGNED DEFAULT NULL,
  `item_blocked_at` int UNSIGNED DEFAULT NULL,
  `item_updated_at` int UNSIGNED DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `items`
--

INSERT INTO `items` (`item_pk`, `item_user_fk`, `item_title`, `item_price`, `item_image`, `item_created_at`, `item_deleted_at`, `item_blocked_at`, `item_updated_at`) VALUES
('3d789600-ea60-404f-86ff-7287e719ea31', 'test', 'Jordbær', 200.00, 'øøø.png', 1732137336, 0, 0, 0),
('50479ff0-9b5a-43f1-b165-44849c2654bb', 'test', 'Æbler', 20.00, '3459f168-9117-4f41-99ab-eaeb9e170287.png', 1732449224, 0, 0, 0),
('89cd812e-2a80-4aee-bcc2-035e7b25dbfb', 'test', 'Cheese', 42.00, 'painting.png', 1732137365, 0, 1732219276, 0),
('addf3539-184a-493a-9edd-7f08eb39f91c', 'test', 'Korn', 20.00, 'øøø.png', 1732176915, 0, 1732219273, 0),
('b0bc50f4-e8aa-4338-a74f-4a68a90cee36', 'test', 'Fløde', 50.00, 'øøø.png', 1732136698, 0, 0, 0),
('d37e76a3-84e1-4b55-b7cb-7b740ba6cd02', 'test', 'Æblexx', 58.00, 'painting.png', 1732137697, 0, 0, 1732178435);

-- --------------------------------------------------------

--
-- Struktur-dump for tabellen `roles`
--

CREATE TABLE `roles` (
  `role_pk` char(36) NOT NULL,
  `role_name` varchar(10) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `roles`
--

INSERT INTO `roles` (`role_pk`, `role_name`) VALUES
('16fd2706-8baf-433b-82eb-8c7fada847da', 'admin'),
('c56a4180-65aa-42ec-a945-5fd21dec0538', 'customer'),
('f47ac10b-58cc-4372-a567-0e02b2c3d479', 'partner'),
('9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15', 'restaurant');

-- --------------------------------------------------------

--
-- Struktur-dump for tabellen `users`
--

CREATE TABLE `users` (
  `user_pk` char(36) NOT NULL,
  `user_name` varchar(20) NOT NULL,
  `user_last_name` varchar(20) NOT NULL,
  `user_email` varchar(100) NOT NULL,
  `user_password` varchar(255) NOT NULL,
  `user_avatar` varchar(50) DEFAULT NULL,
  `user_created_at` int UNSIGNED DEFAULT NULL,
  `user_deleted_at` int UNSIGNED DEFAULT NULL,
  `user_blocked_at` int UNSIGNED DEFAULT NULL,
  `user_updated_at` int UNSIGNED DEFAULT NULL,
  `user_verified_at` int UNSIGNED DEFAULT NULL,
  `user_verification_key` char(36) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `users`
--

INSERT INTO `users` (`user_pk`, `user_name`, `user_last_name`, `user_email`, `user_password`, `user_avatar`, `user_created_at`, `user_deleted_at`, `user_blocked_at`, `user_updated_at`, `user_verified_at`, `user_verification_key`) VALUES
('02290f12-34d3-4b1d-a79a-71ea2caf79ff', 'Steven', 'Melendez', 'mschneider@testsite.org', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_54.jpg', 1732134879, 0, 0, 0, 1732134879, 'e3b24080-bcc2-4854-b16c-88cc29e28f8c'),
('02b00989-b1b0-4172-9d97-3ec5fe35b32f', 'Christopher', '', 'fhopkins@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_6.jpg', 1732134881, 0, 0, 0, 0, '7bc7ce57-817b-4119-af22-accbb6747201'),
('036bfa93-3a0a-4e9b-b3d2-50c1477d33b1', 'Crystal', '', 'restaurant@hotmail.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_9.jpg', 1732134882, 0, 0, 0, 1732134882, '3140605e-8df3-4806-8202-1df0255f4ff6'),
('06893e0a-14b8-47fb-bfdf-764e4b670dfd', 'Douglas', '', 'xavierhughes@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_34.jpg', 1732134883, 0, 0, 0, 0, '57662412-d60b-47e1-926e-6d10580519bc'),
('0a7a08e6-635d-430b-ac88-fb10a89a2237', 'Katie', '', 'hcamacho@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_75.jpg', 1732134880, 0, 0, 0, 0, '21f76842-7014-4aef-8f7a-cba3acd8fbf0'),
('0f584310-c74d-44d5-8f49-e28096ab728c', 'Ernest', 'Anderson', 'rphillips@example.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_13.jpg', 1732134879, 0, 0, 0, 0, 'c5808b4f-be9c-42ac-8146-c691798f769b'),
('0ffc40ac-ed12-4ac4-a929-752631188bb1', 'Todd', 'Stark', 'deansabrina@website.co', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_1.jpg', 1732134879, 0, 0, 0, 1732134879, 'b98025c4-246e-44ca-8429-4862f3cdee88'),
('103acf2f-2926-408b-9dcb-fb9c243fe387', 'Thomas', '', 'brandonblack@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_32.jpg', 1732134882, 0, 0, 0, 1732134882, '314115ee-7b10-4421-af83-469384090216'),
('11f37012-9558-4151-be4c-96929da11c50', 'Cory', 'Miller', 'brianosborne@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_49.jpg', 1732134880, 0, 0, 0, 1732134880, '572863f0-43eb-4b4d-83e2-74c7e66a3fa8'),
('144629a1-15a0-477a-b307-1e51b8c42288', 'John', '', 'ukeith@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_93.jpg', 1732134881, 0, 0, 0, 0, '29fb778b-00dc-40ba-a6a0-48cc40ca4bed'),
('186011b3-8c41-430c-9a6b-10cb10447fc9', 'Christine', '', 'scottkaren@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_70.jpg', 1732134883, 0, 0, 0, 1732134883, '314408ec-b34f-4271-957e-690c080d2322'),
('1b595b82-a163-4fe8-a3da-688f4226494e', 'Brianna', '', 'patrickacevedo@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_78.jpg', 1732134884, 0, 0, 0, 0, 'a5f6e6f6-4450-407f-b1cf-2f4149a1e600'),
('1b8e3e65-55a5-400d-816c-bb730fdca7a7', 'John', 'Conway', 'joshuataylor@testsite.org', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_78.jpg', 1732134879, 0, 0, 0, 1732134879, '1668ea07-56c9-43f8-87b0-41a0e94dba03'),
('1dc0024f-66f5-4678-bf87-4956f4ada333', 'Amanda', 'Mckinney', 'sarahlynch@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_77.jpg', 1732134880, 0, 0, 0, 1732134880, 'a8538952-46db-40ed-980a-d76efb561e3b'),
('1efec1dd-dbaf-415b-a16e-4ce9171bfae7', 'Justin', 'Bright', 'margaret97@gmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_94.jpg', 1732134879, 0, 0, 0, 0, '8360d895-6e3f-4655-8a7e-e6314dff7483'),
('212450c8-c6b4-42bb-b171-d8823142b658', 'Ashley', 'Willis', 'madisonrobertson@website.co', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_78.jpg', 1732134879, 0, 0, 0, 1732134879, '10e19c55-0c4a-4a80-9de6-16fc202aa578'),
('21d566a7-2566-4384-ae1c-e722e8a3b912', 'Joshua', 'Davis', 'chardy@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_71.jpg', 1732134880, 0, 0, 0, 1732134880, '9229f204-be8f-4e36-990e-678554a29899'),
('22c77b78-4d78-4625-bfa6-c9fbb72fd8e0', 'Ryan', 'Walsh', 'bettyjohns@gmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_36.jpg', 1732134879, 0, 0, 0, 1732134879, '7244eac3-1de7-465d-87c3-72d8333422c4'),
('29005479-d41c-481a-b938-3bf5e5caedb2', 'Carl', 'Jackson', 'bboyer@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_80.jpg', 1732134880, 0, 0, 0, 1732134880, '8d40d870-2bc6-4401-95d1-596bf971ebda'),
('2ac67f64-82e5-4c03-bf09-0416472e5832', 'Mark', '', 'martinezsherry@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_9.jpg', 1732134883, 0, 0, 0, 1732134883, '25585c90-2898-43b8-83c6-6e918e086a6a'),
('2c6e8d94-12e4-4259-bb95-20d4972ed350', 'John', 'Partner', 'partner@fulldemo.com', 'scrypt:32768:8:1$p0IkX88zvkbK3uhc$aa791f1c07af6a0ea4e17c5e9ed088d6a697d729df93a66bb6eec0ea6e71fddeee48f160f161fb9678b238b4c796373da55a4b44b54c0cb0c9bd2c04b7f90340', 'profile_12.jpg', 1732134879, 0, 0, 0, 1732134879, '4bb3d783-3772-4296-9d30-ff05aaf0e77e'),
('2f9476ce-7505-464b-885e-2266a2124486', 'James', 'Armstrong', 'krystalrodriguez@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_83.jpg', 1732134879, 0, 0, 0, 0, '0965feec-66a4-421a-b827-4b6229dedb26'),
('31589756-b0c7-41be-9f45-b4340e3dacc9', 'Warren', 'Gibson', 'medinarebecca@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_84.jpg', 1732134880, 0, 0, 0, 0, 'd7d77e37-1cc8-4090-a931-6606542105a2'),
('32dc5cee-7bdb-49a1-8889-7968e35a4433', 'Richard', '', 'browneric@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_28.jpg', 1732134884, 0, 0, 0, 0, '428ca4a2-76cd-4725-a3df-b2acb8d35c9f'),
('341a6f3c-571e-47bb-8436-7441e1ee4cde', 'Julie', 'Eriksen', 'j@hotmail.com', 'scrypt:32768:8:1$wEdjd5DRzv7cMenp$7478780cdf9983ed6e8b284fc3520656f2dba9fe2422699eb707fe44ed56453ddb7f937c78a683ed328ccb46f1cb05cebffaa62d50ddd541094ec112a58ad89a', '', 1732448663, 0, 0, 0, 1732448694, 'd3f496dd-7818-4425-941d-b3b51a288a88'),
('34cb5d92-a703-4dd8-bc6b-44b5e52b4c92', 'Joshua', 'Rodriguez', 'nunezmelissa@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_25.jpg', 1732134880, 0, 0, 0, 0, '6a26df34-4d84-496f-b8ad-21131d29d0e6'),
('386b201c-6320-410b-90f5-96768b40cf5b', 'Joel', 'Livingston', 'abigailknapp@hotmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_74.jpg', 1732134879, 0, 0, 0, 1732134879, 'c7fbb224-793d-4142-a812-580db6dcf73a'),
('394c77de-1544-46dc-b27c-c4f498e75d38', 'Timothy', 'Castillo', 'brooke06@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_98.jpg', 1732134880, 0, 0, 0, 1732134880, 'd79f3d11-ed1d-4ffa-b313-369b2fd3e21e'),
('39e5537c-168f-4e01-9985-ae61a9037cf9', 'Russell', 'Brady', 'charlescopeland@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_90.jpg', 1732134880, 0, 0, 0, 1732134880, '4a89d73a-d560-4df8-9485-5de58227fcbe'),
('3cf7fc49-9c4b-4d48-ad6f-6878aa31d56a', 'Evan', 'Harris', 'nicholas82@gmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_70.jpg', 1732134879, 0, 0, 0, 1732134879, '2cfd27e7-5d50-4941-a719-9d94544e7f3e'),
('3cfebd4f-dfec-4353-98d4-5c6b28fc1dbb', 'William', 'Fernandez', 'josephsmith@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_38.jpg', 1732134879, 0, 0, 0, 1732134879, '262b730e-d068-4ccb-9c54-e7fffed6f9f5'),
('41fdbabb-a595-467b-a730-ef04d88b1fa7', 'Melanie', '', 'joshuashort@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_77.jpg', 1732134884, 0, 0, 0, 0, '32897f9a-b3c5-4935-8f69-5d8e6be7a20a'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'John', 'Customer', 'customer@fulldemo.com', 'scrypt:32768:8:1$lZtctKxFC1XBfTjo$d4ab39a5d89cfb9ed092b168e4f14f57e7207021f545c492fc5dbf1be9a0fc92c22a7ad9be0404c77ce98c2e0c750f550664c1dc5a69288f8c801720088203ad', 'profile_11.jpg', 1732134879, 0, 0, 0, 1732134879, '45a68615-1c62-423f-bf29-ed9e4fbf1f03'),
('4417208f-774a-410c-bb61-cab71220d2ce', 'Alyssa', 'Pittman', 'cfigueroa@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_13.jpg', 1732134880, 0, 0, 0, 1732134880, 'e1a9b9df-8ab6-4e55-bc26-f6284a3f983b'),
('4a8dff58-3a40-4221-ab81-31c2b2c20bcd', 'Trevor', 'Torres', 'katherine88@example.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_7.jpg', 1732134879, 0, 0, 0, 1732134879, 'db22e3d9-4aa0-4f05-9811-ce857cb5d4ae'),
('4d9ab430-d855-4fd7-874f-fc919302bd51', 'Monica', 'Smith', 'michele03@hotmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_36.jpg', 1732134879, 0, 0, 0, 0, 'd598f597-112e-47a1-8ea0-4b378dd02c21'),
('4fd2f2be-85fc-4e29-bad1-8f0ebba0a422', 'William', '', 'clarkdonna@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_30.jpg', 1732134884, 0, 0, 0, 0, '46545037-06e5-4160-acba-08d9a3439816'),
('5704c2f7-d0b2-4c26-93f7-cf7e2a71e868', 'Matthew', 'Sutton', 'mccormickkelsey@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_14.jpg', 1732134879, 0, 0, 0, 1732134879, 'e1c5ef75-d7ad-4c62-a576-ab5fb2c13678'),
('572df695-90e8-4ecd-835d-9abbb1e5f7dd', 'Jessica', 'Smith', 'davidwalker@hotmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_47.jpg', 1732134879, 0, 0, 0, 0, '06e56f14-f8c3-4b39-994c-b80f42b069cc'),
('572ff838-a167-4740-82f2-cc598ecf00b4', 'Alec', 'Stanton', 'matthew21@example.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_10.jpg', 1732134879, 0, 0, 0, 0, 'ef1abe0f-bfe5-4d7f-a7a7-be2de9b8b937'),
('5840e587-fe50-49ff-ba7b-868f443abff1', 'Christine', '', 'johnjones@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_85.jpg', 1732134881, 0, 0, 0, 1732134881, '247dc250-64e3-40c8-86a0-0db94d142e9a'),
('593d29ec-519f-4750-b3af-41b9e2984e08', 'Ian', 'Cooper', 'rebeccamiller@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_41.jpg', 1732134880, 0, 0, 0, 0, '8267c002-6b2f-4f13-a00b-0e66550abd5c'),
('5975d53f-db5f-4a01-a560-c0aa7752192a', 'Derrick', '', 'rmiller@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_71.jpg', 1732134883, 0, 0, 0, 1732134883, '43e94ba8-dedb-4b65-8329-89208b4e5f0f'),
('598e6bfd-b84f-47c0-9abd-d4a81e61a4a7', 'Jennifer', 'Webb', 'nburch@hotmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_55.jpg', 1732134879, 0, 0, 0, 1732134879, '7f4818ee-abe9-4c75-bbd0-6a1068618f26'),
('59b3dcd8-727d-4227-bda4-071be1e7770f', 'Laura', 'Conrad', 'jamesromero@example.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_90.jpg', 1732134879, 0, 0, 0, 1732134879, '8ff3b4ae-5480-4109-bab0-051133e0d7bc'),
('5a433a9d-4dfe-428b-bf09-9cd9c291d8a0', 'Gregory', 'Sanchez', 'sandersnicholas@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_29.jpg', 1732134880, 0, 0, 0, 0, 'de039883-8db8-4d7e-85dc-66f6571bd5c4'),
('5db20391-aa58-44c8-9a5f-723eec806f47', 'Lisa', 'Wu', 'pearsonmichael@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_91.jpg', 1732134880, 0, 0, 0, 0, 'dfdbc828-808f-4781-86df-affe5919493c'),
('60757563-c3fc-4c61-bba8-c8af2ec7a0ee', 'Derek', 'Obrien', 'anthony25@gmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_81.jpg', 1732134879, 0, 0, 0, 1732134879, '27b2d81f-f5f0-425d-8d3b-c365d8b6bf5d'),
('62310a6f-6ba0-4251-8242-c388f260c629', 'Jeffrey', '', 'cwalker@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_88.jpg', 1732134884, 0, 0, 0, 0, '64dc7721-42b4-4640-ac35-442997fce974'),
('635f8a0f-1900-4013-b1e7-b6095f67b610', 'Logan', 'Cunningham', 'hoovercaleb@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_96.jpg', 1732134879, 0, 0, 0, 0, 'cacd2da9-87d1-4fb8-a920-751521590f13'),
('64a5633e-c6ee-4aba-86f7-dc43aad8e68c', 'Charles', 'Harris', 'louis94@gmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_19.jpg', 1732134879, 0, 0, 0, 1732134879, '3ed7a81c-d212-49ee-9f8b-4f38f5619834'),
('6504b96b-8ae3-4476-b050-82138ff5dc3e', 'John', 'Restaurant', 'restaurant@fulldemo.com', 'scrypt:32768:8:1$6qSGmkZftT8NRZNm$f051695e628a90b527bc0df058375a82f7208f4def99576e23d30e2d7e1c748fae6561d5ced318e68bc75da2b7a1bfd65fc39fa62d5d90d62193af18ac0ac6f1', 'profile_13.jpg', 1732134879, 0, 0, 0, 1732134879, 'aaba93b1-2d72-49b3-b84d-93db5322b29f'),
('6771e9ae-58d0-44ff-9962-8c49a132ddab', 'Michelle', 'Smith', 'davidsonbenjamin@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_21.jpg', 1732134880, 0, 0, 0, 1732134880, '45d4f67c-428b-47c5-856f-41ece15d4acf'),
('69684716-4c95-4732-8bc4-5b9c4a4a189a', 'Bradley', 'Ward', 'jwilliams@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_94.jpg', 1732134880, 0, 0, 0, 1732134880, 'ddeb0f45-83ef-4cd4-865e-b4d29fefc6de'),
('6aa89db7-11fa-468f-8c50-728a3f90fdb2', 'Kenneth', 'Powell', 'amandabrennan@gmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_91.jpg', 1732134879, 0, 0, 0, 0, '9583f0fd-27ec-4e77-8fa0-ac5130cc6df5'),
('6d33bf2a-0be7-4385-b59d-09768a708f93', 'Stephanie', 'White', 'shawn86@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_69.jpg', 1732134880, 0, 0, 0, 0, 'b8455942-7db8-41f8-83dc-5e659f2d1980'),
('6fff792e-ea34-4bfc-a394-f024045d4ad5', 'Sonya', 'Stout', 'melissa34@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_51.jpg', 1732134880, 0, 0, 0, 0, '23c42301-63dc-4c2e-98d1-2d68c9a71ee8'),
('75798692-5475-41e5-adb2-889fe64f8321', 'Derrick', 'King', 'chasealfred@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_44.jpg', 1732134880, 0, 0, 0, 0, '9c6bba8c-7a26-4535-b6ca-f9ec81037677'),
('75ba4b73-cc0d-4a25-9811-b2840fffed1d', 'Kristen', '', 'garciawilliam@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_51.jpg', 1732134882, 0, 0, 0, 1732134882, '7ae26d01-192b-425a-a42d-7454a6fac609'),
('766ee32f-6eb5-4399-bbee-ff2903045dc5', 'Matthew', 'Weaver', 'ruiznorma@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_67.jpg', 1732134880, 0, 0, 0, 1732134880, '35d2846c-ec80-4cf0-bee7-2ad83268b276'),
('777ec85f-f8b2-4cd1-bdd7-a8b90aea15ae', 'Elizabeth', 'Richards', 'cadams@example.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_28.jpg', 1732134879, 0, 0, 0, 0, '5a47d9d5-3ec1-42aa-943e-cdfbce1bc196'),
('786fcb28-fc51-490b-962f-7b457cd8fa85', 'Stacy', 'Carlson', 'guerrabrandon@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_12.jpg', 1732134880, 0, 0, 0, 1732134880, 'f9fde7d0-67da-4af6-a7f3-605a7126ab55'),
('7a24a5c1-88ce-4da2-99a2-ed995f2c2780', 'Becky', 'Foster', 'sanchezbrenda@testsite.org', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_1.jpg', 1732134879, 0, 0, 0, 0, '57dd17f4-e0a0-4977-86ad-1985181dce12'),
('7bbba910-ffa9-4611-b408-9ed93a33cfaa', 'Rhonda', '', 'jennifer90@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_72.jpg', 1732134881, 0, 0, 0, 1732134881, '3bc5ed99-d4cd-4493-8ae4-8032569c67f9'),
('81084467-46da-4108-b61d-5470b8b01478', 'Douglas', '', 'pricerebecca@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_88.jpg', 1732134882, 0, 0, 0, 0, '82e5bf54-9b76-4a3e-8679-ad3ee001514c'),
('8337505b-f6a7-4839-ae69-a02b582179ab', 'Howard', 'Santiago', 'michelledawson@gmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_93.jpg', 1732134879, 0, 0, 0, 0, '2bdcdda0-2983-430d-a37b-e0d89005685f'),
('83feabe9-e1b1-4132-87e8-9151822df9dc', 'Timothy', 'Wright', 'jwong@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_62.jpg', 1732134880, 0, 0, 0, 0, '794dc789-10e3-4b45-977a-6b42e11d4f11'),
('844c5acd-b804-4ad3-8d3d-9334aa55242c', 'Tim', 'Williams', 'kgriffin@example.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_4.jpg', 1732134879, 0, 0, 0, 1732134879, 'd1ec1321-653f-4fea-ab9a-68b33b97d9c2'),
('84b0adc1-9496-4dc0-80ff-83bd07f8072e', 'Mark', 'Brown', 'cassandra93@fakemail.io', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_85.jpg', 1732134879, 0, 0, 0, 0, '2665c733-dc4c-4b33-89ab-5a0a070d6477'),
('8587eb3c-0d92-40fb-8465-714bae036fb0', 'partner', 'partner', 'partner@hotmail.com', 'scrypt:32768:8:1$5jr8fxO6Ti835CvF$8534654459d6f58b60d9fee2342a949de1278c6d2f3d1fe111a10c32661e3367cc381fe10234b4db499aa4b2bd929a9d3effb08bbd0ba62a6d25a0d60144022f', '', 1732222888, 0, 0, 0, 1732222922, 'ff7c53b3-8f79-4778-a3dd-15f0ba7cc979'),
('85bb9e67-e4e1-442d-a8df-9c1762502b2e', 'Noah', '', 'qtownsend@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_61.jpg', 1732134881, 0, 0, 0, 0, '5acb3496-e65b-46d0-aa2e-e950fda03581'),
('8651a7c1-4350-458b-b18a-a2a397363ac4', 'Kristina', '', 'joseph87@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_38.jpg', 1732134880, 0, 0, 0, 0, '3e9c2198-4413-459d-b87b-8c59b6da3c05'),
('86b0a497-9993-4f36-ab63-d595bbc9fbde', 'Christine', 'Pham', 'bethanywilson@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_34.jpg', 1732134880, 0, 0, 0, 1732134880, '010d001f-0643-462e-a74a-51d5a9b7e2ed'),
('87b261f5-2c7f-4802-bc84-77b71f1f7b40', 'Jill', 'Fisher', 'kurt62@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_31.jpg', 1732134879, 0, 0, 0, 0, '84fb03e8-35b4-4910-8e08-ab5e00bee440'),
('88c105c7-c547-48e4-9ff5-4e57784dd82e', 'Shelby', '', 'jeffreyperry@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_64.jpg', 1732134880, 0, 0, 0, 1732134880, '8b7b961f-f43e-45c5-98fe-66ca1132764b'),
('8a6c07d4-5ef3-4a7b-b734-bb7d97cdf786', 'Kathryn', '', 'watsonjennifer@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_62.jpg', 1732134884, 0, 1732218512, 0, 1732134884, '4a5853d0-8f47-4bc7-8b75-53fd3ca05436'),
('8e9e3a5a-e3c3-43c2-9fd5-8f3887e78f53', 'Megan', '', 'tonyagray@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_56.jpg', 1732134881, 0, 0, 0, 0, 'a853f56c-6a05-411d-b606-9c701ee4fbee'),
('8fa24b4f-ad8c-42a5-8a6e-fb786fa99ef6', 'Kenneth', 'Keith', 'matthewblackburn@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_18.jpg', 1732134880, 0, 0, 0, 1732134880, 'bc287cc6-6a85-48b4-9db3-77a3068fe46c'),
('90f5b0f3-8656-400b-9aeb-1f95c1bc1792', 'Laura', 'Montgomery', 'piercerick@gmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_64.jpg', 1732134879, 0, 0, 0, 0, 'dfcd562e-076f-486b-91e4-8a57e3897d59'),
('90f780a4-481e-4df9-aef8-b32e99c38961', 'Nicole', '', 'mmanning@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_32.jpg', 1732134884, 0, 1732218560, 0, 1732134884, '5d8afb81-c30a-4069-a7de-157815aee7b5'),
('90ff5222-9193-425c-8535-c6899d84b5ec', 'Brandi', '', 'hallmichele@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_87.jpg', 1732134884, 0, 0, 0, 0, 'e73406d1-06f8-4425-9bd5-01da42cc3015'),
('946ded76-0e02-4f4c-b162-c173f75d14c2', 'Christopher', '', 'walkerthomas@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_21.jpg', 1732134883, 0, 0, 0, 1732134883, 'c5b439a5-7d00-49e2-8eeb-76998437a4f8'),
('9515d089-63ee-4a47-8cd6-8b36ba64ad81', 'Jessica', 'Mason', 'aaron65@website.co', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_99.jpg', 1732134879, 0, 0, 0, 0, '955521ee-2917-4c32-a887-4194cc77f8a7'),
('951e7764-b0dc-4a4f-8247-367d52706d9f', 'James', '', 'davismichael@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_90.jpg', 1732134883, 0, 0, 0, 1732134883, 'b89edcea-662f-4f51-8e87-e52282d503c0'),
('95d770dd-31a7-448f-8e14-529663e82434', 'Randy', 'Johns', 'ehampton@gmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_3.jpg', 1732134879, 0, 0, 0, 0, '2d0fa5c6-08d3-4b70-bf3a-8f85e2e7dd92'),
('96fc9d05-b6ab-46b4-8c31-dc6cab84e0e1', 'Michael', '', 'masonjulie@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_6.jpg', 1732134881, 0, 0, 0, 0, '3c2adbe2-554d-4033-9c51-869292df7895'),
('97ffaec1-12f6-47d9-9725-eecdf0a0bb86', 'John', 'Brown', 'joneskayla@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_30.jpg', 1732134880, 0, 0, 0, 1732134880, '66484d42-afec-487a-9ed4-bd844982863d'),
('98abcc91-329c-4afa-8c07-008df34b67fb', 'Elizabeth', 'Green', 'josephnicholson@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_82.jpg', 1732134880, 0, 0, 0, 1732134880, 'aef2847d-85e1-4809-8e1e-f1f3f6bea73b'),
('9a0a8a52-220f-45c1-be55-6c07888ae5c2', 'Diana', 'Tucker', 'clarkamy@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_53.jpg', 1732134880, 0, 0, 0, 1732134880, '0d846678-82b0-4b5c-99e7-0ec30bcb5c52'),
('9a86dc76-b6d4-4ca8-87a3-ac24a2bd30f4', 'Scott', 'Garcia', 'kylie32@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_2.jpg', 1732134880, 0, 0, 0, 0, '9162aacf-0d6d-4c71-9ad4-8688be5f021c'),
('9b2540e9-f9b8-4485-a89e-580d14fdbd78', 'Erin', '', 'njohnson@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_37.jpg', 1732134884, 0, 0, 0, 0, '410d61d5-cdce-4acf-be2c-c759329415f7'),
('9cf2b46f-ff5c-4bcd-93ed-50ef4ac7151f', 'Michelle', '', 'josephhebert@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_52.jpg', 1732134882, 0, 0, 0, 0, '2228d794-d581-463b-9899-0f445dac0fda'),
('9e34e4bf-469c-44e1-bdd8-ff2ff8654bd2', 'Jason', 'Rios', 'amanda33@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_43.jpg', 1732134880, 0, 0, 0, 0, '66284b90-bf45-49fb-81d8-71c850b8658a'),
('9fb02f83-86f9-4d38-95dd-3058f13568eb', 'Victoria', 'Jones', 'andrew83@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_47.jpg', 1732134880, 0, 0, 0, 1732134880, '79f39d44-d96c-4610-8e44-63e21b5aa2b1'),
('9fda6a60-0c78-4a50-b1ef-f598f2320a3e', 'Lynn', 'Harris', 'angela66@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_63.jpg', 1732134880, 0, 0, 0, 0, '84258fa5-4101-4c82-b25d-4e5dbef760e9'),
('a0a7cea6-4b93-4f0a-9454-7b259292dd4d', 'John', 'Holder', 'brewerjennifer@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_98.jpg', 1732134880, 0, 0, 0, 1732134880, 'bac36682-4939-45e9-9bb1-fd82d03ed408'),
('a0a96f13-aa87-42cf-9a67-36637a7953bc', 'Wendy', '', 'smithwalter@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_62.jpg', 1732134880, 0, 0, 0, 1732134880, '0e2ee198-4a4c-45e4-ab0a-17a3421270b9'),
('a5b16f7e-5803-46da-b85f-2d38537ffcf9', 'Brian', 'Shannon', 'latashawiley@example.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_23.jpg', 1732134879, 0, 0, 0, 0, 'c2df34d9-4d07-43be-9092-4973460c3c1b'),
('a5b6c592-abfd-4c2f-9526-080546fc3946', 'Theresa', '', 'jeremyvance@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_54.jpg', 1732134883, 0, 0, 0, 1732134883, '90a106c8-fb71-4cb2-a0a6-8debe552316b'),
('a6265e28-41a9-46b2-8bd8-0984eef7f066', 'Marcus', 'Martin', 'llong@hotmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_65.jpg', 1732134879, 0, 0, 0, 0, '07042307-7678-4e02-97d3-b2c84b9a7edf'),
('a6f49852-67a2-4a07-a9bd-eb14c19ba79b', 'Lauren', '', 'zanderson@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_23.jpg', 1732134883, 0, 0, 0, 0, 'd5892617-1ece-4ec4-a176-8beb1e80848f'),
('a7276786-da95-46b2-8702-0afbd88f6a47', 'Sheila', 'Adams', 'claymatthew@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_68.jpg', 1732134880, 0, 0, 0, 1732134880, 'f7b00b6a-ff71-444b-b5bf-b7262fed1bd7'),
('a8310519-55ca-494f-a2dc-02996e51cf1a', 'Chelsea', 'Doyle', 'kevincurtis@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_38.jpg', 1732134880, 0, 0, 0, 0, '7e3b7212-1653-46be-a93d-20b124f04f5a'),
('a8eced36-3216-4838-8f48-d767ed8ccbeb', 'Veronica', 'Walker', 'fletchersheila@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_2.jpg', 1732134880, 0, 0, 0, 1732134880, '858b806b-6e4d-4693-8641-7c8a2a1b0bff'),
('aa71c8bb-59af-4bce-983a-48b7721baccd', 'Julie', 'Jones', 'lawrence23@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_75.jpg', 1732134880, 0, 0, 0, 0, '5c02ad4e-e2d4-4c15-80b8-0e0e7851d6b9'),
('ad3a7b19-e0f0-4c33-a391-ff72219dfda0', 'Katherine', 'Skinner', 'bennettjenna@fakemail.io', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_36.jpg', 1732134879, 0, 0, 0, 0, 'f748a71f-5732-4657-8da7-44a469c4c280'),
('adbfbe04-457d-4b50-8418-915429524131', 'Michael', '', 'nashjulie@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_54.jpg', 1732134882, 0, 0, 0, 1732134882, '9ffbf81d-10cb-4e3a-a9dd-16f43cacd45a'),
('b105bf57-46c7-49f3-b90d-ca0bc60b432c', 'Rita', 'Miller', 'johnsonrebecca@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_89.jpg', 1732134880, 0, 0, 0, 0, '36ad301d-118c-4225-931a-e5605843b16a'),
('b291d8a7-327e-4af7-a9f5-98505304b500', 'Melissa', 'Morgan', 'briandonaldson@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_9.jpg', 1732134880, 0, 0, 0, 0, 'd5377ec4-80e1-44a7-bf79-7a594f924a40'),
('b348ba8b-2aba-4747-8469-f0bb238ce1ea', 'Ann', 'Kennedy', 'sandersamanda@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_87.jpg', 1732134880, 0, 0, 0, 1732134880, '51a85fac-b06b-4894-888c-3de4483631bd'),
('b381accd-6951-43d8-b19b-a141a1b0a553', 'Rebecca', '', 'fschmidt@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_53.jpg', 1732134881, 0, 0, 0, 1732134881, '97bdda85-1147-4d77-bb50-73cbe7f1cd8e'),
('b7391b0d-c230-4eae-a317-8fc26e0ed33a', 'Scott', 'Cook', 'chaddawson@testsite.org', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_74.jpg', 1732134879, 0, 0, 0, 0, 'e3af4dfd-02fd-4205-bf6a-c5a8f4e54699'),
('b863a871-6811-4ec2-b913-5da6ff8bb639', 'Jason', 'Lee', 'rasmussenrobert@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_19.jpg', 1732134879, 0, 0, 0, 1732134879, '11f4f1a1-f36f-4c50-be8d-8006f0c7c080'),
('bb2b465e-bc14-41c5-b0d9-1fe4141eaeab', 'Michael', 'Cunningham', 'vtaylor@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_97.jpg', 1732134879, 0, 0, 0, 0, '158f759d-69a5-4dcf-9b71-2608280385f5'),
('bd3fab1e-32d4-4db4-a57a-8626fbfebac1', 'Caitlin', '', 'barnettjames@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_63.jpg', 1732134881, 0, 0, 0, 0, '4f751d0a-4716-42ff-af6d-b59ede91d2c6'),
('bd435875-15d2-4f0a-9ea9-d84dbecaf578', 'Hannah', '', 'johnsonmartha@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_2.jpg', 1732134883, 0, 0, 0, 1732134883, '79fea147-9fe3-4a90-8d17-5b55fe3c3d65'),
('c650e1e8-4f44-4401-9e6e-a10beaed2313', 'Don', '', 'davidthornton@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_61.jpg', 1732134882, 0, 0, 0, 0, '7660cf5e-c20c-4b4f-91f9-f1985f0cd7cc'),
('c6b1f76e-063c-4666-b48b-9a65e21f29e4', 'Ricky', '', 'davidhamilton@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_68.jpg', 1732134882, 0, 0, 0, 0, '7f037902-1873-4b28-b3bc-f529adf66fe9'),
('c6c88f36-8806-49d5-934a-f26055acc00e', 'Katie', '', 'lozanochristina@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_1.jpg', 1732134883, 0, 0, 0, 0, 'e04b975e-b7ec-4e39-88d0-c1178b2e7316'),
('c7761951-c9b7-4f0d-8227-d0be2ca8974f', 'Darren', '', 'bjackson@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_39.jpg', 1732134882, 0, 0, 0, 1732134882, '40d761b3-a535-4438-b7c2-b9966d43a9f7'),
('ccab12a5-a5d8-4f2a-858c-5179ad48660c', 'Erica', 'Vargas', 'yoliver@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_48.jpg', 1732134879, 0, 0, 0, 1732134879, '9c12e2b5-2435-400d-8e83-012bfcbeb44e'),
('ccea3d62-f1de-4257-9603-ead9fd7ebddd', 'Catherine', 'Boyd', 'wesleylucas@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_20.jpg', 1732134880, 0, 0, 0, 0, 'c8a0b060-9d1e-487f-b106-d06dba19de4a'),
('ce800905-8e19-4897-b55f-40cb22d720a7', 'William', 'Fowler', 'sandra57@website.co', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_56.jpg', 1732134879, 0, 0, 0, 0, '2e2de453-e299-47ee-b97a-b3117e43a8a5'),
('d34d4f69-5f09-4c0e-91f0-fe2a1c729d16', 'Bryan', 'Welch', 'megannichols@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_82.jpg', 1732134880, 0, 0, 0, 0, 'df15cbcd-3e5d-475d-ae7d-081e4dc8a525'),
('db31a6fe-d6b8-4089-834a-e7416a9a455c', 'Anthony', 'Finley', 'monroejustin@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_51.jpg', 1732134880, 0, 0, 0, 0, 'b09b79ea-8df8-4680-ad0f-fcf4f24dec28'),
('dcc21b70-6f14-447c-8de2-9c29add4da12', 'Erica', 'Banks', 'heather28@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_55.jpg', 1732134880, 0, 0, 0, 1732134880, '221b3c67-f271-48d3-af98-ec0e32629403'),
('dd2728d6-35d4-451f-9fc5-fe5a4bdfd0a1', 'Vincent', 'Hutchinson', 'bbrown@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_1.jpg', 1732134880, 0, 0, 0, 1732134880, 'f3b21ae0-4316-4940-9035-27f8e9bdcfe2'),
('dd3849dd-8650-46a3-a8ab-3a913e6b8d53', 'Carolyn', '', 'juliaaguilar@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_19.jpg', 1732134884, 0, 0, 0, 1732134884, '918dfb28-63d0-4186-9116-eae288ce0cd6'),
('de4eeb92-0cff-49ca-b346-74a49f885f1a', 'Alexander', 'Johnson', 'diane02@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_18.jpg', 1732134880, 0, 0, 0, 1732134880, '81a8a2f4-0a9c-4c2c-a08c-f16f3fa1c1a1'),
('df081f71-1983-4ce6-8f8a-da7070819b2b', 'Amy', '', 'gbrown@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_87.jpg', 1732134881, 0, 0, 0, 0, '563b1c85-2071-434c-983a-80821244cc86'),
('df4aeae3-7e89-4fdb-b08b-934e87bec2a4', 'Theresa', 'Christian', 'whitekaitlyn@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_85.jpg', 1732134879, 0, 0, 0, 1732134879, '3b18cf6d-9ffd-43d8-bcf1-d78fc0177a4d'),
('e0128ab5-f35c-4eb4-8d79-da25cf883b34', 'Christopher', 'Nelson', 'mcknightrachel@fakemail.io', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_41.jpg', 1732134879, 0, 0, 0, 0, '85d86811-c161-4a4a-b256-d7e3b9639b63'),
('e1224c54-7cf5-41dd-a058-0ab781a72737', 'Sarah', 'Hill', 'fullermichael@testsite.org', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_45.jpg', 1732134879, 0, 0, 0, 1732134879, '860ac262-b1e7-4f15-9fde-69a10ce88a9d'),
('e4cc13c3-4903-40b4-8ac4-6a4f31775468', 'Erica', 'Lopez', 'christopher33@testsite.org', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_68.jpg', 1732134879, 0, 0, 0, 0, '8fa3323f-0ef6-481b-aca3-67b7cf433b98'),
('e7037b8c-70c7-4b8d-9fe9-2a33e7606fa3', 'Ashley', 'Harrell', 'scotthoward@example.com', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_33.jpg', 1732134880, 0, 0, 0, 0, 'dc4a9fee-6ce0-4cbd-a1a7-bc6265794c68'),
('e78b8144-d03e-4d46-acec-90ec30eaf4de', 'Shawn', 'Thompson', 'beckerkenneth@example.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_1.jpg', 1732134879, 0, 0, 0, 0, 'c443d52a-5832-453a-bdef-c2c0a5321b97'),
('ea0ce089-8caf-4fc9-8222-bce3ecc12273', 'Douglas', 'Graham', 'yvonne25@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_59.jpg', 1732134880, 0, 0, 0, 0, 'd787d6d6-1718-4db3-b62d-2ce1bca71732'),
('ea4d3f62-78c1-4abe-a09f-492bd118c81c', 'Jason', '', 'cameronrobinson@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_33.jpg', 1732134880, 0, 0, 0, 0, 'f281f775-9aa2-403d-aaf5-f0a3f8493383'),
('ea51251d-0caa-463f-b5f7-3d41111e17ce', 'Melissa', 'Gomez', 'jyoung@testsite.org', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_96.jpg', 1732134879, 0, 0, 0, 0, '6f8a05f0-55d2-4e65-93f6-6328880bb9e5'),
('ed947cea-e3f0-49d8-a5f1-1748a93ce460', 'Richard', 'Chase', 'kelli55@example.net', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_69.jpg', 1732134880, 0, 0, 0, 1732134880, '842e3711-e710-47fd-946f-7664b02fa61b'),
('ee175724-42f2-4532-967e-8c035a85d0b4', 'Carolyn', 'Salazar', 'fletcherjoel@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_30.jpg', 1732134880, 0, 0, 0, 1732134880, '2f2c06be-42f6-4c3d-be9d-65731712b8a6'),
('ee52066b-a603-456a-81dd-a82d0982c17c', 'Gerald', '', 'harriskristin@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_9.jpg', 1732134883, 0, 0, 0, 0, '9318eee0-9225-4be1-bc62-78ee97aa88c7'),
('eea7439d-49bc-4390-b846-2fc7c82787fa', 'Clinton', 'Johnson', 'alexandra49@mydomain.net', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_54.jpg', 1732134879, 0, 0, 0, 1732134879, '1a465214-c3ed-4061-bc93-5661340457db'),
('eeb2b834-ece4-43b9-9e7d-6dfc7ba001e1', 'Sean', '', 'curryrichard@example.com', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_51.jpg', 1732134882, 0, 0, 0, 1732134882, '6c784bbe-d2f7-4444-8d79-71caf5535b0a'),
('ef3f2f1d-77e3-491d-b75b-1886f65726e9', 'Wesley', 'Bishop', 'gregorygarner@website.co', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_99.jpg', 1732134879, 0, 0, 0, 1732134879, 'd49793e6-d412-41ff-bf0c-7457f544bd52'),
('f10d6905-4734-4d67-af0d-7ec637d34522', 'Randy', 'Moore', 'usmith@testsite.org', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_70.jpg', 1732134879, 0, 0, 0, 1732134879, '7bf0d562-2e17-4ac3-b84a-f6807779e9ee'),
('f14eaba7-5e33-4054-bbed-279d4764386f', 'Leonard', 'Peterson', 'tina74@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_10.jpg', 1732134880, 0, 0, 0, 0, 'c80a01aa-9f49-44b8-b9a7-63d5c6ae39e5');
INSERT INTO `users` (`user_pk`, `user_name`, `user_last_name`, `user_email`, `user_password`, `user_avatar`, `user_created_at`, `user_deleted_at`, `user_blocked_at`, `user_updated_at`, `user_verified_at`, `user_verification_key`) VALUES
('f151f15d-3a04-4e7f-ad52-2ee74a119837', 'Santiago', 'Donoso', 'admin@fulldemo.com', 'scrypt:32768:8:1$EfGRU1N3GP2HInJU$6ea253dac8dcdfd77ba00148609ab68b78267efe95f75046dc6c5d22cce100df35e5265f3bf58234e429834b1eafa36ad2ec5aa6fe96a3ce6915984c5f9153b4', 'profile_10.jpg', 1732134879, 0, 0, 1732448788, 1732134879, '92cb5bc3-7cca-4d71-94dc-ce729a6bb330'),
('f1a37ba3-e333-4eda-a4f5-a49f5a9ce65a', 'Michael', '', 'aaronwalker@example.org', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_35.jpg', 1732134885, 0, 1732219264, 0, 1732134885, '1de17853-673b-48dd-bb8f-d85d604afcb8'),
('f211aa04-06be-4b21-af60-39311e6848db', 'Heather', 'Moses', 'stephen09@testsite.org', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_7.jpg', 1732134879, 0, 0, 0, 1732134879, 'e714c9f1-8854-4d0f-8a8f-016877c01048'),
('f2ee3f32-0853-41c3-96e7-a42697679ccf', 'Michael', 'Robinson', 'mooreaaron@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_60.jpg', 1732134880, 0, 0, 0, 1732134880, 'faefeb5a-f5ed-4759-b0f3-01510ac66084'),
('f2f81ddc-d480-4f04-8380-6d939b525aef', 'Francisco', 'Davidson', 'troberts@example.org', 'scrypt:32768:8:1$NdIYoqZKLUOw0AFj$5ea86b3e877d7f9429bf07438901d761df0879feea07e8946b06c1762bb3168891a5e9001d5b1f757a7fd000dc566b3da6b85a316bb9dee194d2155ece92fa7d', 'profile_46.jpg', 1732134880, 0, 0, 0, 1732134880, '3a965c76-9138-4a84-aa7a-c9bc28cda62d'),
('f93cb8a3-078f-4ea9-80d4-950862a15ec0', 'Michelle', '', 'richvicki@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_4.jpg', 1732134881, 0, 0, 0, 1732134881, '7122eec3-1ee5-44ca-82e4-87dc8255f7cf'),
('fa149c86-a73e-478d-a269-79de9e0e9abc', 'Katherine', 'Morris', 'schaney@hotmail.com', 'scrypt:32768:8:1$qTUexZNWiBTspUAv$9024ac70a9b9b4e6295b8ee655d1aea08070ac6f6284fa192aa4fa2a6b349f19aceccbb4f1ec08ca78f74661eec221710c04fafe2b70b3e147000cf010a65d1b', 'profile_18.jpg', 1732134879, 0, 0, 0, 1732134879, '8790ce5f-195a-47b1-b4a2-72f1d61ccc4d'),
('fab91f4b-8750-4ee6-8745-ffd3ec013eec', 'John', '', 'brownscott@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_63.jpg', 1732134881, 0, 0, 0, 0, '34e23f5e-96cd-4fdb-90cb-d64529769970'),
('fb31225e-8a3a-4168-8794-e6f1a1c1a7df', 'Jacqueline', '', 'gibsonjesus@example.net', 'scrypt:32768:8:1$hPCwWEZayiuG3rsh$0b1a637cf9b76f3c6441f683c6ae3c6f2cabf014e58ca6f6f52a79cfe0a50d39e70faa0d98008631218508a217d57d7999da16c928ca6be9114e6239fc098e4a', 'profile_69.jpg', 1732134883, 0, 0, 0, 1732134883, '63588e1c-9cbc-4e8a-a0a5-5e373431b3c7');

-- --------------------------------------------------------

--
-- Struktur-dump for tabellen `users_roles`
--

CREATE TABLE `users_roles` (
  `user_role_user_fk` char(36) NOT NULL,
  `user_role_role_fk` char(36) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `users_roles`
--

INSERT INTO `users_roles` (`user_role_user_fk`, `user_role_role_fk`) VALUES
('f151f15d-3a04-4e7f-ad52-2ee74a119837', '16fd2706-8baf-433b-82eb-8c7fada847da'),
('02b00989-b1b0-4172-9d97-3ec5fe35b32f', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('036bfa93-3a0a-4e9b-b3d2-50c1477d33b1', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('06893e0a-14b8-47fb-bfdf-764e4b670dfd', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('0a7a08e6-635d-430b-ac88-fb10a89a2237', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('103acf2f-2926-408b-9dcb-fb9c243fe387', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('144629a1-15a0-477a-b307-1e51b8c42288', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('186011b3-8c41-430c-9a6b-10cb10447fc9', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('1b595b82-a163-4fe8-a3da-688f4226494e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('2ac67f64-82e5-4c03-bf09-0416472e5832', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('32dc5cee-7bdb-49a1-8889-7968e35a4433', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('41fdbabb-a595-467b-a730-ef04d88b1fa7', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('4fd2f2be-85fc-4e29-bad1-8f0ebba0a422', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('5840e587-fe50-49ff-ba7b-868f443abff1', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('5975d53f-db5f-4a01-a560-c0aa7752192a', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('62310a6f-6ba0-4251-8242-c388f260c629', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('6504b96b-8ae3-4476-b050-82138ff5dc3e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('75ba4b73-cc0d-4a25-9811-b2840fffed1d', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('7bbba910-ffa9-4611-b408-9ed93a33cfaa', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('81084467-46da-4108-b61d-5470b8b01478', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('85bb9e67-e4e1-442d-a8df-9c1762502b2e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('8651a7c1-4350-458b-b18a-a2a397363ac4', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('88c105c7-c547-48e4-9ff5-4e57784dd82e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('8a6c07d4-5ef3-4a7b-b734-bb7d97cdf786', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('8e9e3a5a-e3c3-43c2-9fd5-8f3887e78f53', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('90f780a4-481e-4df9-aef8-b32e99c38961', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('90ff5222-9193-425c-8535-c6899d84b5ec', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('946ded76-0e02-4f4c-b162-c173f75d14c2', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('951e7764-b0dc-4a4f-8247-367d52706d9f', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('96fc9d05-b6ab-46b4-8c31-dc6cab84e0e1', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('9b2540e9-f9b8-4485-a89e-580d14fdbd78', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('9cf2b46f-ff5c-4bcd-93ed-50ef4ac7151f', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('a0a96f13-aa87-42cf-9a67-36637a7953bc', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('a5b6c592-abfd-4c2f-9526-080546fc3946', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('a6f49852-67a2-4a07-a9bd-eb14c19ba79b', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('adbfbe04-457d-4b50-8418-915429524131', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('b381accd-6951-43d8-b19b-a141a1b0a553', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('bd3fab1e-32d4-4db4-a57a-8626fbfebac1', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('bd435875-15d2-4f0a-9ea9-d84dbecaf578', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('c650e1e8-4f44-4401-9e6e-a10beaed2313', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('c6b1f76e-063c-4666-b48b-9a65e21f29e4', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('c6c88f36-8806-49d5-934a-f26055acc00e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('c7761951-c9b7-4f0d-8227-d0be2ca8974f', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('dd3849dd-8650-46a3-a8ab-3a913e6b8d53', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('df081f71-1983-4ce6-8f8a-da7070819b2b', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('ea4d3f62-78c1-4abe-a09f-492bd118c81c', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('ee52066b-a603-456a-81dd-a82d0982c17c', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('eeb2b834-ece4-43b9-9e7d-6dfc7ba001e1', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('f1a37ba3-e333-4eda-a4f5-a49f5a9ce65a', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('f93cb8a3-078f-4ea9-80d4-950862a15ec0', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('fab91f4b-8750-4ee6-8745-ffd3ec013eec', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('fb31225e-8a3a-4168-8794-e6f1a1c1a7df', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('02290f12-34d3-4b1d-a79a-71ea2caf79ff', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('0f584310-c74d-44d5-8f49-e28096ab728c', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('0ffc40ac-ed12-4ac4-a929-752631188bb1', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('1b8e3e65-55a5-400d-816c-bb730fdca7a7', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('1efec1dd-dbaf-415b-a16e-4ce9171bfae7', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('212450c8-c6b4-42bb-b171-d8823142b658', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('22c77b78-4d78-4625-bfa6-c9fbb72fd8e0', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('2f9476ce-7505-464b-885e-2266a2124486', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('341a6f3c-571e-47bb-8436-7441e1ee4cde', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('386b201c-6320-410b-90f5-96768b40cf5b', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('3cf7fc49-9c4b-4d48-ad6f-6878aa31d56a', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('3cfebd4f-dfec-4353-98d4-5c6b28fc1dbb', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('4a8dff58-3a40-4221-ab81-31c2b2c20bcd', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('4d9ab430-d855-4fd7-874f-fc919302bd51', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('5704c2f7-d0b2-4c26-93f7-cf7e2a71e868', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('572df695-90e8-4ecd-835d-9abbb1e5f7dd', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('572ff838-a167-4740-82f2-cc598ecf00b4', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('598e6bfd-b84f-47c0-9abd-d4a81e61a4a7', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('59b3dcd8-727d-4227-bda4-071be1e7770f', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('60757563-c3fc-4c61-bba8-c8af2ec7a0ee', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('635f8a0f-1900-4013-b1e7-b6095f67b610', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('64a5633e-c6ee-4aba-86f7-dc43aad8e68c', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('6aa89db7-11fa-468f-8c50-728a3f90fdb2', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('777ec85f-f8b2-4cd1-bdd7-a8b90aea15ae', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('7a24a5c1-88ce-4da2-99a2-ed995f2c2780', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('8337505b-f6a7-4839-ae69-a02b582179ab', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('844c5acd-b804-4ad3-8d3d-9334aa55242c', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('84b0adc1-9496-4dc0-80ff-83bd07f8072e', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('87b261f5-2c7f-4802-bc84-77b71f1f7b40', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('90f5b0f3-8656-400b-9aeb-1f95c1bc1792', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('9515d089-63ee-4a47-8cd6-8b36ba64ad81', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('95d770dd-31a7-448f-8e14-529663e82434', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('a5b16f7e-5803-46da-b85f-2d38537ffcf9', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('a6265e28-41a9-46b2-8bd8-0984eef7f066', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('ad3a7b19-e0f0-4c33-a391-ff72219dfda0', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('b7391b0d-c230-4eae-a317-8fc26e0ed33a', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('b863a871-6811-4ec2-b913-5da6ff8bb639', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('bb2b465e-bc14-41c5-b0d9-1fe4141eaeab', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('ccab12a5-a5d8-4f2a-858c-5179ad48660c', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('ce800905-8e19-4897-b55f-40cb22d720a7', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('df4aeae3-7e89-4fdb-b08b-934e87bec2a4', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('e0128ab5-f35c-4eb4-8d79-da25cf883b34', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('e1224c54-7cf5-41dd-a058-0ab781a72737', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('e4cc13c3-4903-40b4-8ac4-6a4f31775468', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('e78b8144-d03e-4d46-acec-90ec30eaf4de', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('ea51251d-0caa-463f-b5f7-3d41111e17ce', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('eea7439d-49bc-4390-b846-2fc7c82787fa', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('ef3f2f1d-77e3-491d-b75b-1886f65726e9', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('f10d6905-4734-4d67-af0d-7ec637d34522', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('f211aa04-06be-4b21-af60-39311e6848db', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('fa149c86-a73e-478d-a269-79de9e0e9abc', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('11f37012-9558-4151-be4c-96929da11c50', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('1dc0024f-66f5-4678-bf87-4956f4ada333', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('21d566a7-2566-4384-ae1c-e722e8a3b912', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('29005479-d41c-481a-b938-3bf5e5caedb2', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('2c6e8d94-12e4-4259-bb95-20d4972ed350', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('31589756-b0c7-41be-9f45-b4340e3dacc9', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('34cb5d92-a703-4dd8-bc6b-44b5e52b4c92', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('394c77de-1544-46dc-b27c-c4f498e75d38', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('39e5537c-168f-4e01-9985-ae61a9037cf9', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('4417208f-774a-410c-bb61-cab71220d2ce', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('593d29ec-519f-4750-b3af-41b9e2984e08', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('5a433a9d-4dfe-428b-bf09-9cd9c291d8a0', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('5db20391-aa58-44c8-9a5f-723eec806f47', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('6771e9ae-58d0-44ff-9962-8c49a132ddab', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('69684716-4c95-4732-8bc4-5b9c4a4a189a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('6d33bf2a-0be7-4385-b59d-09768a708f93', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('6fff792e-ea34-4bfc-a394-f024045d4ad5', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('75798692-5475-41e5-adb2-889fe64f8321', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('766ee32f-6eb5-4399-bbee-ff2903045dc5', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('786fcb28-fc51-490b-962f-7b457cd8fa85', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('83feabe9-e1b1-4132-87e8-9151822df9dc', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('8587eb3c-0d92-40fb-8465-714bae036fb0', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('86b0a497-9993-4f36-ab63-d595bbc9fbde', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('8fa24b4f-ad8c-42a5-8a6e-fb786fa99ef6', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('97ffaec1-12f6-47d9-9725-eecdf0a0bb86', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('98abcc91-329c-4afa-8c07-008df34b67fb', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('9a0a8a52-220f-45c1-be55-6c07888ae5c2', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('9a86dc76-b6d4-4ca8-87a3-ac24a2bd30f4', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('9e34e4bf-469c-44e1-bdd8-ff2ff8654bd2', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('9fb02f83-86f9-4d38-95dd-3058f13568eb', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('9fda6a60-0c78-4a50-b1ef-f598f2320a3e', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('a0a7cea6-4b93-4f0a-9454-7b259292dd4d', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('a7276786-da95-46b2-8702-0afbd88f6a47', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('a8310519-55ca-494f-a2dc-02996e51cf1a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('a8eced36-3216-4838-8f48-d767ed8ccbeb', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('aa71c8bb-59af-4bce-983a-48b7721baccd', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('b105bf57-46c7-49f3-b90d-ca0bc60b432c', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('b291d8a7-327e-4af7-a9f5-98505304b500', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('b348ba8b-2aba-4747-8469-f0bb238ce1ea', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ccea3d62-f1de-4257-9603-ead9fd7ebddd', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('d34d4f69-5f09-4c0e-91f0-fe2a1c729d16', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('db31a6fe-d6b8-4089-834a-e7416a9a455c', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('dcc21b70-6f14-447c-8de2-9c29add4da12', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('dd2728d6-35d4-451f-9fc5-fe5a4bdfd0a1', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('de4eeb92-0cff-49ca-b346-74a49f885f1a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('e7037b8c-70c7-4b8d-9fe9-2a33e7606fa3', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ea0ce089-8caf-4fc9-8222-bce3ecc12273', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ed947cea-e3f0-49d8-a5f1-1748a93ce460', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ee175724-42f2-4532-967e-8c035a85d0b4', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('f14eaba7-5e33-4054-bbed-279d4764386f', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('f2ee3f32-0853-41c3-96e7-a42697679ccf', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('f2f81ddc-d480-4f04-8380-6d939b525aef', 'f47ac10b-58cc-4372-a567-0e02b2c3d479');

--
-- Begrænsninger for dumpede tabeller
--

--
-- Indeks for tabel `items`
--
ALTER TABLE `items`
  ADD PRIMARY KEY (`item_pk`);

--
-- Indeks for tabel `roles`
--
ALTER TABLE `roles`
  ADD PRIMARY KEY (`role_pk`),
  ADD UNIQUE KEY `role_name` (`role_name`);

--
-- Indeks for tabel `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`user_pk`),
  ADD UNIQUE KEY `user_email` (`user_email`);

--
-- Indeks for tabel `users_roles`
--
ALTER TABLE `users_roles`
  ADD PRIMARY KEY (`user_role_user_fk`,`user_role_role_fk`),
  ADD KEY `user_role_role_fk` (`user_role_role_fk`);

--
-- Begrænsninger for dumpede tabeller
--

--
-- Begrænsninger for tabel `users_roles`
--
ALTER TABLE `users_roles`
  ADD CONSTRAINT `users_roles_ibfk_1` FOREIGN KEY (`user_role_user_fk`) REFERENCES `users` (`user_pk`) ON DELETE CASCADE ON UPDATE RESTRICT,
  ADD CONSTRAINT `users_roles_ibfk_2` FOREIGN KEY (`user_role_role_fk`) REFERENCES `roles` (`role_pk`) ON DELETE CASCADE ON UPDATE RESTRICT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
