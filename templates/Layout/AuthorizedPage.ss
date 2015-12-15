<div class="content-container unit size3of4 lastUnit">
	<article>
		<h1>$Title</h1>
		<div class="content">
			<% loop $Messages %>
			<% if $Type = error %>
				<p style="color:red;font-weight:bold;">$Message</p>
			<% else %>
				<p style="color:blue;font-weight:bold;">$Message</p>
			<% end_if %>
			<% end_loop %>
			$Content</div>
	</article>
		$Form
		$CommentsForm
</div>