<?php
//Get the base-64 string from data
$filteredData=substr($_POST['img_val'], strpos($_POST['img_val'], ",")+1);

//Decode the string
$unencodedData=base64_decode($filteredData);

//Save the image
file_put_contents('img.png', $unencodedData);
?>
<a href="index.php"><img style="width: 70px;margin:5px 20px 14px 20px;display:inline;" src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAIVcZHVkU4V1bHWWjoWeyP/ZyLe3yP////L/////////////////////////////////////////////////////2wBDAY6WlsivyP/Z2f//////////////////////////////////////////////////////////////////////////wAARCAEfAS8DASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwCvRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFWIcFPpT8D0qXIVypRUs4wwPrUVNO4woqaAdTUuB6UnKwrlSippxwDUNNO4woqSEZfPoKnwPSk5WFcqUVYlwENQxnDimndANoq3gelIygqRip5guVaKKUcmrGJRVsAAdKMD0qOYVypRSkYJFJVjCirSLhAMdqXA9KjmFcqUU+U5c1LDgp9KpuyuBXoq3gelQzjDA+tJSuFyKiipoB1NNuwyGireB6VFOOAaSlcVyGiipIRl8+gpt2GR0VbwPSmS4CGlzC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QAUUUUAFFFFABRRRQAUnTmlooGVaKVuGNJWpqFFFFABRRRQAUUUUAFFFFABToxlxTakhHJNJ7CexNRRRWZkFFFFABRRRQAUUUUAFFFFABVWrVVauJcRV+8PrVmqy/eH1qzRIJBRRRUEBRRRQAUUUUAFFFFABRRRQAUUUUARSr/FUVWSMjBquw2kirizSLEoooqigooooAKKKKACiiigAqwi7VqONMnJ6VNUyfQiT6BRRRUEBRRRQAUUUUAFFFFABRRRQAVVq1VWriXEVfvD61Zqsv3h9as0SCQUUUVBAUUUUAFFFFABRRRQAUUUUAFFFFABTXUMPenUUDK7KVPNNqyQCMGo2i9DVqRakRUU4ow7UnSqKEopQCegzThGx7UAMp6R7uvAqRY1HXmn1Ll2IcuwgGBilooqCAooooAKKKKACiiigAooooAKKKKACqtWqq1cS4ig4ORVgHIzVapomyMHtRIcloSUUUVBmFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABSYB7UtFACYxS0UUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFACHoc9KrVNK3G3vUNXHY0itApVYqcikoqiiwjBhTqrAkdDipFl/vVDj2IcexLRTQwOORzTsUrE2CijFGKQBRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRiml1HcU7BYdTWYKMmmNL/AHfzqMnJyaaj3KUe4E5OaSiirLCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//Z" alt="" /></a>
<div style="margin-left:50px;">
<h2 style="display:inline;padding:-18px 0 0 0">Webshooter - Remotely screenshot any website!</h2>
<h3>How this program work?</h3> 
<h5>Import a website locally through a local proxy for avoid same-origin policy limitations.<br> Print full page canvas into your browser & save the result to server.<br> By this way the screenshot take the size of your browser window, so you can arrange it just by resizing your browser!<br>Have fun!</h5>
<table>
    <tr>
        <td>
            <a href="img.png" target="blank">
            	Shot image server link</a>
        </td>
        <td align="right" style="margin:0 400px 0 0">

        </td>
    </tr>
    <tr>
        <td colspan="2">
            <br />
            <br />
			<span>
		
			</span>
            <br />
<?php
//Show the image
echo '<img style="margin:0 10% 0 10%;max-width:40%;" width="auto" heigth="auto" src="'.$_POST['img_val'].'" />';
?>
        </td>
    </tr>
</table>
<style type="text/css">
body, a, span {
	font-family: Tahoma; font-size: 10pt; font-weight: bold;
}
</style>
